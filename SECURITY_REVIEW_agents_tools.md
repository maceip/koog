# Security Review: `agents/agents-tools/` Module

**Review Date:** 2026-07-20
**Scope:** `agents/agents-tools/src/commonMain/` and `agents/agents-tools/src/jvmMain/`
**Reviewer:** Automated Security Audit

---

## Threat Model

The primary attacker in this module's threat model is a **compromised or adversarial LLM**. The LLM generates tool call messages (tool name + JSON arguments) that flow through the framework into tool execution. An attacker who controls or influences LLM output (via prompt injection, model compromise, or malicious API proxy) controls:

1. The `tool` name field in `Message.Tool.Call`
2. The `content` JSON string containing tool arguments
3. The structure, types, and extra fields within that JSON

The trust boundary is between the LLM response parser and the tool execution layer.

---

## Finding 1: `ignoreUnknownKeys = true` Enables Silent Extra-Field Injection

**Severity: LOW (Design Trade-off)**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/serialization/ToolSerialization.kt`, lines 13-18
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/Tool.kt`, line 43 (uses `ToolJson`)

**Description:**
The global `ToolJson` configuration sets `ignoreUnknownKeys = true`:

```kotlin
public val ToolJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
    decodeEnumsCaseInsensitive = true
}
```

This means any JSON object passed as tool arguments can contain arbitrary extra keys that are silently discarded during deserialization. For `@Serializable` data classes, extra fields are ignored.

**Attack Path:**
An adversarial LLM sends `{"expected_arg": "value", "admin": true, "role": "superuser"}` as tool arguments. The extra `admin` and `role` fields are silently dropped.

**Impact Assessment:**
For `@Serializable` data class-based tools (the standard path), this is **not exploitable** because kotlinx.serialization strictly maps JSON keys to declared fields — extra keys are discarded, not mapped to unintended fields. There is no mass assignment vulnerability because the target types are compile-time fixed.

However, this reduces defense-in-depth: if a tool implementation ever manually parses the raw JSON alongside the deserialized args, extra fields could leak through.

**Real End-to-End Exploit Chain:** No. The serialization framework prevents extra fields from affecting the deserialized object. This is a defense-in-depth concern, not an active vulnerability.

---

## Finding 2: Reflection-Based `ToolFromCallable` Uses `callSuspendBy` with Deserialized Arguments

**Severity: LOW-MEDIUM (Contextual Risk)**

**Location:**
- `agents/agents-tools/src/jvmMain/kotlin/ai/koog/agents/core/tools/reflect/ToolFromCallable.kt`, lines 99-108

**Description:**
The `execute` method directly invokes arbitrary Kotlin callables via reflection:

```kotlin
override suspend fun execute(args: VarArgs): Any? {
    val instanceParameter = callable.instanceParameter
    val argsMap = if (instanceParameter != null) {
        val thisRefToCall = thisRef ?: error("Instance parameter is null")
        args.args + (instanceParameter to thisRefToCall)
    } else {
        args.args
    }
    return callable.callSuspendBy(argsMap)
}
```

The `args.args` map is populated by `VarArgsSerializer.deserialize()` which reads JSON fields and maps them to `KParameter` objects by index.

**Attack Path:**
An adversarial LLM crafts JSON arguments that, after deserialization, become the exact parameter values passed to `callable.callSuspendBy()`. The LLM controls the values of all parameters that are exposed in the tool descriptor.

**Mitigations Already Present:**
1. **`ensureValid()` check (lines 76-97):** At construction time, every VALUE parameter is verified to be serializable via `serializerOrNull()`, and the return type must also be serializable. Non-serializable parameters are rejected.
2. **Registration-time binding:** The callable is fixed at tool registration time; the LLM cannot choose *which* callable to invoke, only the arguments to an already-registered callable.
3. **Serialization boundary:** Arguments go through kotlinx.serialization, which enforces type constraints (Int stays Int, String stays String, etc.).

**Impact Assessment:**
The risk is limited to the power of the callable that was registered. If developers register dangerous functions as tools (e.g., shell execution, file system operations, database queries), an adversarial LLM can invoke them with arbitrary arguments. This is by design — but the framework provides no guardrails (rate limiting, argument sanitization, or scope restriction) beyond type checking.

**Real End-to-End Exploit Chain:** Partially — only if a tool performs a sensitive operation (like executing shell commands) and the LLM is compromised. The framework does not introduce new attack surface beyond what the tool itself exposes.

---

## Finding 3: `VarArgsSerializer` Parameter-Index Mapping May Silently Skip Arguments

**Severity: LOW**

**Location:**
- `agents/agents-tools/src/jvmMain/kotlin/ai/koog/agents/core/tools/reflect/ToolFromCallable.kt`, lines 158-175

**Description:**
The `VarArgsSerializer.deserialize()` method maps JSON fields to `KParameter` objects by the element index returned from `decodeElementIndex(descriptor)`. If an element index corresponds to a non-serializable parameter (like the `this` reference, tagged with `NON_SERIALIZABLE_PARAMETER_PREFIX`), the deserializer reads `kCallable.parameters[parameterDecodedIndex]` which could reference the `this` parameter.

```kotlin
override fun deserialize(decoder: Decoder): VarArgs {
    val argumentMap = mutableMapOf<KParameter, Any?>()
    decoder.beginStructure(descriptor).apply {
        while (true) {
            val parameterDecodedIndex = decodeElementIndex(descriptor)
            if (parameterDecodedIndex == CompositeDecoder.DECODE_DONE) break
            if (parameterDecodedIndex == CompositeDecoder.UNKNOWN_NAME) continue
            val parameter = kCallable.parameters[parameterDecodedIndex]
            val parameterSerializer = serializer(parameter.type)
            val paramValue = this.decodeNullableSerializableElement(...)
            argumentMap[parameter] = paramValue
        }
        ...
    }
}
```

If a malicious JSON payload includes a field with the name `__##nonSerializableParameter##__#0` (the synthesized name for the instance parameter), the decoder might match it to the instance parameter's index. However, in `execute()`, the instance parameter is overwritten with `thisRef`:

```kotlin
val argsMap = if (instanceParameter != null) {
    val thisRefToCall = thisRef ?: error("Instance parameter is null")
    args.args + (instanceParameter to thisRefToCall)
} else {
    args.args
}
```

The `+` operation on maps means the `instanceParameter` from `args.args` would be overwritten by the legitimate `thisRef`.

**Impact Assessment:**
The `this` parameter cannot be hijacked because `execute()` always overwrites it with the real `thisRef`. However, the synthetic parameter name (`__##nonSerializableParameter##__#N`) being predictable and matched via JSON keys is an unnecessary attack surface.

**Real End-to-End Exploit Chain:** No. The `thisRef` override in `execute()` prevents exploitation.

---

## Finding 4: `executeUnsafe` Relies on Unchecked Cast with Generic Type Erasure

**Severity: LOW (Internal API)**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/Tool.kt`, lines 91-97

**Description:**
```kotlin
@InternalAgentToolsApi
public suspend fun executeUnsafe(args: Any?): TResult {
    return withUnsafeCast<TArgs, TResult>(
        args,
        "executeUnsafe argument must be castable to TArgs"
    ) { execute(it) }
}
```

Due to JVM type erasure, the `@Suppress("UNCHECKED_CAST")` in `withUnsafeCast` means the cast `input as T` may not fail immediately for generic types. For example, if `TArgs` is `List<String>` but `args` is `List<Int>`, the cast succeeds (both are `List` at runtime) and the type mismatch only surfaces later when elements are accessed.

**Attack Path:**
In `GenericAgentEnvironment.processToolCall()` (line 84), the code casts the tool:
```kotlin
(tool as Tool<Any?, Any?>).execute(toolArgs)
```

This bypasses `executeUnsafe` entirely and calls `execute` directly with a cast. If `toolArgs` (the deserialized result of `decodeArgs`) has an unexpected type, the error would only manifest inside the tool's `execute` implementation.

**Mitigations Already Present:**
1. `executeUnsafe` is annotated `@InternalAgentToolsApi`, signaling it's not for external use.
2. The actual call chain in `GenericAgentEnvironment` first calls `tool.decodeArgs(toolArgsJson)` which returns a properly-typed `TArgs`, so the subsequent `execute(toolArgs)` receives the correct type.
3. The `@Suppress("UNCHECKED_CAST")` on the environment call is safe because `decodeArgs` already guarantees type correctness.

**Impact Assessment:**
No practical exploit. The `decodeArgs` step acts as a type-safe gate before `execute` is called.

**Real End-to-End Exploit Chain:** No. Deserialization enforces types before execution.

---

## Finding 5: Schema-Descriptor Mismatch — No Runtime Schema Enforcement

**Severity: MEDIUM (Design Gap)**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/SerialToToolDescription.kt`, lines 110-159 (`asToolDescriptor`)
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/Tool.kt`, line 105 (`decodeArgs`)

**Description:**
The `ToolDescriptor` (which describes parameters to the LLM) and the actual `KSerializer` (which performs deserialization) are generated independently and there is no runtime check that they are consistent.

The `ToolDescriptor` tells the LLM what parameters to provide with what types. The `KSerializer` (via `decodeArgs`) actually deserializes the JSON. These two sources of truth can diverge in several ways:

1. **Manual descriptor construction:** If a developer creates a `ToolDescriptor` manually with incorrect parameter types or names, the LLM receives wrong schema information, but deserialization still works differently.

2. **Reflection-based tools (`ToolFromCallable`):** The descriptor is generated by `KFunction.asToolDescriptor()` using `KType.asToolType()`, while deserialization uses `VarArgsSerializer` which calls `serializer(parameter.type)`. These use different code paths — one maps Kotlin types to `ToolParameterType`, the other to kotlinx.serialization serializers. Complex types (data classes, sealed classes, Maps) could produce descriptor/serializer mismatches.

3. **Polymorphic/Sealed/Map types:** In `asToolDescriptor` (lines 148-157), sealed classes, objects, contextual types, open polymorphic types, and maps all produce an empty `ToolDescriptor` (no required or optional parameters). But the actual serializer *will* attempt to deserialize fields. This means the LLM gets no schema guidance, but arbitrary JSON structures can be sent and will be deserialized.

**Attack Path:**
For tools using polymorphic/sealed/Map argument types, the LLM receives no schema constraints. An adversarial LLM (or a prompt-injected LLM) could pass arbitrary JSON structures that the serializer might accept. For `Map<String, String>` parameters, the attacker can inject arbitrary key-value pairs.

**Impact Assessment:**
The severity depends on what tools use these complex types. For most tools using `@Serializable data class` args, the descriptor and serializer are consistent. The risk is higher for:
- Tools accepting `Map<String, *>` parameters (arbitrary key injection)
- Tools using polymorphic types (class discriminator injection)

**Real End-to-End Exploit Chain:** Possible for tools with Map/polymorphic argument types where the LLM is adversarial. The LLM can inject arbitrary key-value pairs or select unexpected polymorphic subtypes.

---

## Finding 6: `decodeEnumsCaseInsensitive = true` Bypasses Schema Enum Validation

**Severity: INFORMATIONAL**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/serialization/ToolSerialization.kt`, line 17

**Description:**
The `ToolJson` configuration includes `decodeEnumsCaseInsensitive = true`. While the `ToolDescriptor` exposes enum values as exact-case strings (e.g., `["RED", "GREEN", "BLUE"]`), the deserializer accepts any case variant (e.g., `"red"`, `"Red"`, `"rEd"`).

**Impact Assessment:**
This is a usability feature, not a security issue. However, it means the schema communicated to the LLM is more restrictive than what the deserializer actually accepts, which is the opposite of the security-ideal configuration (schema should be at least as restrictive as the deserializer).

**Real End-to-End Exploit Chain:** No practical security impact.

---

## Finding 7: Exception Messages Leak Internal Type Information

**Severity: LOW (Information Disclosure)**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/Tool.kt`, lines 231-248 (`withUnsafeCast`)
- `agents/agents-core/src/commonMain/kotlin/ai/koog/agents/core/environment/GenericAgentEnvironment.kt`, lines 67-80, 85-107

**Description:**
When deserialization or execution fails, error messages containing internal type names, parameter names, and stack trace information are returned to the LLM:

```kotlin
// GenericAgentEnvironment.kt line 76
content = "Tool with name '$toolName' failed to parse arguments due to the error: ${e.message}"
// line 103
content = "Tool with name '$toolName' failed to execute due to the error: ${e.message}!"
```

Additionally, `withUnsafeCast` produces detailed error messages:
```kotlin
"Unsafe cast failed in tool with name: $name"
"Error message: $errorMessage"
"Original ClassCastException message: ${e.message}"
```

**Attack Path:**
An adversarial LLM can deliberately send malformed arguments to trigger error messages, then use the returned error information (class names, parameter types, serialization details) to refine subsequent attack payloads.

**Impact Assessment:**
This is a standard information disclosure concern. In the LLM agent context, the LLM already has access to the tool descriptors (which reveal parameter names and types), so the incremental information gain from error messages is modest. However, error messages may reveal internal implementation details (package names, class hierarchies) not present in descriptors.

**Real End-to-End Exploit Chain:** Partial — useful for reconnaissance in a multi-step attack, but not directly exploitable.

---

## Finding 8: `ToolFromCallable` Parameter Validation Gap — `s` (String) Parameter Accepted for Missing Name

**Severity: INFORMATIONAL**

**Location:**
- `agents/agents-tools/src/jvmMain/kotlin/ai/koog/agents/core/tools/reflect/ToolFromCallable.kt`, lines 120-134 (`VarArgsSerializer.descriptor`)

**Description:**
In the `VarArgsSerializer`, when building the `SerialDescriptor`, parameters without names (like the `this` parameter) are given synthetic names `__##nonSerializableParameter##__#N` and their serializer falls back to `NothingSerializer()`. These are marked as optional.

However, the `NothingSerializer()` cannot actually serialize or deserialize any value — attempting to deserialize a value for such a parameter would throw an exception. This is safe because the parameter is marked as optional and would only be triggered if the JSON explicitly includes the synthetic key name.

**Impact Assessment:** No security impact. The synthetic parameter name is unlikely to appear in legitimate or adversarial JSON, and even if it did, `NothingSerializer` would throw before any harm.

**Real End-to-End Exploit Chain:** No.

---

## Finding 9: No Input Size Limits or Depth Limits on JSON Deserialization

**Severity: MEDIUM (Denial of Service)**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/Tool.kt`, line 105 (`decodeArgs`)
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/serialization/ToolSerialization.kt`, lines 11-18 (`ToolJson`)

**Description:**
There are no limits on:
- Total JSON payload size for tool arguments
- JSON nesting depth
- Array length within tool arguments
- String value length within tool arguments

The `ToolJson` configuration and `decodeArgs` method accept arbitrarily large or deeply nested JSON.

**Attack Path:**
An adversarial LLM (or a compromised LLM API proxy) sends extremely large JSON payloads as tool arguments:
- Deeply nested objects/arrays to cause stack overflow during deserialization
- Very large arrays to cause OOM
- Very long strings to consume memory

In practice, the LLM API response itself has size limits (most LLM providers cap output tokens), so the practical payload size is bounded by the LLM provider. However, if the tool call content is sourced from an MCP server or other non-LLM source, these limits don't apply.

**Impact Assessment:**
Denial of service via resource exhaustion. Bounded in the standard LLM case by provider output limits, but unbounded when tool calls originate from MCP or other programmatic sources.

**Real End-to-End Exploit Chain:** Yes, for MCP-sourced tool calls. Partial for LLM-sourced calls (limited by provider token limits, typically 4K-32K tokens).

---

## Finding 10: `Tool<*, *>` Type Erasure in `ToolRegistry` and `GenericAgentEnvironment`

**Severity: LOW**

**Location:**
- `agents/agents-tools/src/commonMain/kotlin/ai/koog/agents/core/tools/ToolRegistry.kt`, line 31 (stores `Tool<*, *>`)
- `agents/agents-core/src/commonMain/kotlin/ai/koog/agents/core/environment/GenericAgentEnvironment.kt`, line 84

**Description:**
Tools are stored as `Tool<*, *>` in the registry, losing type information. When executing, the environment casts:

```kotlin
(tool as Tool<Any?, Any?>).execute(toolArgs)
```

This cast is safe because `toolArgs` comes from `tool.decodeArgs()` which returns the correct `TArgs` type. However, the pattern relies on the invariant that `decodeArgs` and `execute` are called on the same `tool` instance. If a different tool's `decodeArgs` result were passed to another tool's `execute`, the type mismatch would not be caught until runtime.

**Impact Assessment:** The invariant is maintained in all current call sites. This is a code quality observation, not an exploitable vulnerability.

**Real End-to-End Exploit Chain:** No.

---

## Summary Table

| # | Finding | Severity | Exploitable E2E? | Attacker |
|---|---------|----------|-------------------|----------|
| 1 | `ignoreUnknownKeys` silently drops extra fields | LOW | No | Adversarial LLM |
| 2 | Reflection `callSuspendBy` with LLM-controlled args | LOW-MEDIUM | Only if dangerous tools registered | Adversarial LLM |
| 3 | VarArgs parameter-index mapping & synthetic names | LOW | No (thisRef override) | Adversarial LLM |
| 4 | `executeUnsafe` unchecked cast with type erasure | LOW | No (deserialization gate) | Internal misuse |
| 5 | Schema-descriptor/serializer mismatch for complex types | MEDIUM | Yes, for Map/polymorphic args | Adversarial LLM |
| 6 | Case-insensitive enum decoding bypasses schema | INFORMATIONAL | No | N/A |
| 7 | Exception messages leak internal type information | LOW | Partial (reconnaissance) | Adversarial LLM |
| 8 | Synthetic parameter name with NothingSerializer | INFORMATIONAL | No | N/A |
| 9 | No input size/depth limits on JSON deserialization | MEDIUM | Yes (DoS via MCP) | Adversarial LLM/MCP |
| 10 | Type erasure in registry/environment | LOW | No | Internal misuse |

---

## Recommendations

1. **Consider adding a strict deserialization mode** for security-sensitive deployments that rejects unknown keys (`ignoreUnknownKeys = false`). This could be an opt-in configuration on the `Tool` class.

2. **Add JSON payload size and depth limits** to `ToolJson` or at the `decodeArgs` call site. This is especially important for MCP-sourced tool calls which don't have LLM token limits as a natural bound.

3. **Sanitize error messages** returned to the LLM to avoid leaking internal implementation details. Return generic "invalid arguments" messages instead of raw exception messages.

4. **Add schema consistency validation** that verifies the `ToolDescriptor` matches the `KSerializer`'s expectations at tool registration time, especially for reflection-based tools.

5. **Document the security model** for tool developers, making clear that registered tools must implement their own input validation since the framework only provides type-level checking, not semantic validation.

6. **For `ToolFromCallable`**, consider adding an allowlist mechanism or capability-based access control to restrict which callables can be registered as tools.
