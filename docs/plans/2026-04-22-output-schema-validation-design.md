# Output Schema Validation Design (SEC-29)

**Goal:** Validate LLM responses against a caller-supplied expected type, catching malformed JSON and prompt-injected schema violations (OWASP LLM05). Implemented as a standard AI.Sentinel detector using ZeroAlloc.Serialisation for zero-reflection deserialization.

**Architecture:** New `OutputSchemaDetector` in the Security category. Runs only when `SentinelOptions.ExpectedResponseType` is set. On the response scan pass, deserializes the last assistant message via `ISerializerDispatcher.Deserialize`. Failure (malformed JSON, missing required fields, type mismatch) produces `High` severity — routed through the existing intervention engine like any other detection.

**Tech Stack:** `ZeroAlloc.Serialisation` (source-generated `ISerializerDispatcher`), `ZeroAlloc.Inject` (`[Singleton]` DI registration), `System.Text.Json` via the `SystemTextJson` backend.

---

## Architecture

One new detector + one option. No new error type, no new pipeline concept.

### OutputSchemaDetector

```csharp
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class OutputSchemaDetector(
    SentinelOptions options,
    ISerializerDispatcher dispatcher) : IDetector
{
    private static readonly DetectorId _id = new("SEC-29");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;
    // ...
}
```

**Fires only when:**
- `options.ExpectedResponseType` is not null
- Context contains at least one `ChatRole.Assistant` message (response scan pass)

On the prompt scan pass, there is no assistant message, so the detector returns clean in a single loop — cost is effectively a null check + iterator.

### ISerializerDispatcher dependency

`ISerializerDispatcher` is a ZeroAlloc.Serialisation interface. Callers register an implementation via the source-generated `AddSerializerDispatcher()` extension. If absent, `OutputSchemaDetector`'s constructor fails at DI resolution with a standard "Unable to resolve service" error.

### Ecosystem requirement

Response types must be annotated:

```csharp
[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]
public sealed record WeatherResponse(string City, double TemperatureC);
```

This is consistent with other ZeroAlloc-based annotation patterns in the project (`[Instrument]`, `[RateLimit]`, `[Singleton]`, etc.).

---

## Validation logic

```csharp
public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
{
    if (options.ExpectedResponseType is not Type expected)
        return ValueTask.FromResult(_clean);

    string? responseText = null;
    for (var i = ctx.Messages.Count - 1; i >= 0; i--)
    {
        if (ctx.Messages[i].Role == ChatRole.Assistant && ctx.Messages[i].Text is { Length: > 0 } t)
        {
            responseText = t;
            break;
        }
    }
    if (responseText is null) return ValueTask.FromResult(_clean);

    var jsonText = ExtractJson(responseText);
    var bytes = Encoding.UTF8.GetBytes(jsonText);

    try
    {
        var deserialized = dispatcher.Deserialize(bytes, expected);
        if (deserialized is null)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Response deserialized to null for type {expected.Name}"));
        return ValueTask.FromResult(_clean);
    }
    catch (JsonException ex)
    {
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
            $"Response failed schema validation for {expected.Name}: {ex.Message}"));
    }
    catch (NotSupportedException)
    {
        // Type not registered with the dispatcher — caller misconfiguration.
        return ValueTask.FromResult(_clean);
    }
}

private static string ExtractJson(string text)
{
    var trimmed = text.AsSpan().Trim();
    if (!trimmed.StartsWith("```")) return text;

    var afterFence = trimmed[3..];
    var newline = afterFence.IndexOf('\n');
    if (newline < 0) return text;

    var body = afterFence[(newline + 1)..];
    var closing = body.LastIndexOf("```", StringComparison.Ordinal);
    return closing < 0 ? text : body[..closing].ToString();
}
```

### Behavior table

| Input | Result |
|---|---|
| `ExpectedResponseType` null | `Clean` |
| No assistant message (prompt scan) | `Clean` |
| Valid JSON matching type | `Clean` |
| Malformed JSON (`JsonException`) | `High` with exception message in reason |
| Missing required property | `High` |
| Deserializes to `null` (caller sent literal `"null"`) | `High` |
| Type not registered with dispatcher (`NotSupportedException`) | `Clean` (misconfiguration, not a threat) |

### JSON extraction

LLMs frequently wrap JSON in markdown code fences even when asked for raw JSON. The `ExtractJson` helper unwraps ```` ```json ... ``` ```` or ```` ``` ... ``` ```` patterns. Pure JSON responses pass through unchanged.

### Severity

Fixed at `High`. Users tune intervention via the standard `opts.OnHigh` mapping — same story as every other detector. No new configuration knobs.

---

## SentinelOptions addition

```csharp
/// <summary>Optional expected response type for structured-output LLM calls.
/// When set, <c>OutputSchemaDetector</c> attempts to deserialize each assistant response
/// as this type via the registered <c>ISerializerDispatcher</c>.
/// The type must be annotated with <c>[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]</c>.</summary>
public Type? ExpectedResponseType { get; set; }
```

No validator change — `null` is a valid state (validation disabled).

---

## DI wiring

No explicit detector registration needed — the `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` attribute is picked up by the existing `services.AddAISentinelDetectors()` call via the ZeroAlloc.Inject source generator.

`ISerializerDispatcher` must be registered by the caller:

```csharp
builder.Services.AddSerializerDispatcher(); // ZeroAlloc.Serialisation extension
```

If the caller sets `ExpectedResponseType` but forgets the dispatcher registration, DI fails fast at startup with "Unable to resolve service for type 'ISerializerDispatcher'".

Package reference added to `AI.Sentinel.csproj`:

```xml
<PackageReference Include="ZeroAlloc.Serialisation" Version="1.3.*" />
```

---

## Testing

### OutputSchemaDetectorTests (new)

| Test | Verifies |
|---|---|
| `ExpectedTypeNotSet_ReturnsClean` | `ExpectedResponseType = null` → clean regardless of content |
| `NoAssistantMessage_ReturnsClean` | Only user messages → clean (prompt scan path) |
| `ValidJson_MatchesType_ReturnsClean` | Well-formed response deserializes → clean |
| `MalformedJson_ReturnsHigh` | Broken JSON → High, reason contains exception message |
| `MissingRequiredProperty_ReturnsHigh` | JSON missing a required field → High |
| `WrappedInCodeFence_IsExtracted` | ```` ```json\n{...}\n``` ```` → unwrapped, deserialized, clean |
| `NullDeserialization_ReturnsHigh` | Response text is `"null"` → High |

Test fixture needs a `[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]` POCO + the generated dispatcher from the test project.

### SentinelPipelineTests (integration)

| Test | Verifies |
|---|---|
| `ExpectedType_Configured_ThroughPipeline_ReturnsThreatDetected` | Full pipeline path: prompt clean, response fails schema, intervention engine returns `ThreatDetected` |

---

## Files changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel/Detectors/Security/OutputSchemaDetector.cs` |
| Modify | `src/AI.Sentinel/SentinelOptions.cs` — add `ExpectedResponseType` |
| Modify | `src/AI.Sentinel/AI.Sentinel.csproj` — add `ZeroAlloc.Serialisation 1.3.*` |
| New | `tests/AI.Sentinel.Tests/Detectors/Security/OutputSchemaDetectorTests.cs` |
| Modify | `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` — add `ZeroAlloc.Serialisation.SystemTextJson` + generator |
| Modify | `tests/AI.Sentinel.Tests/SentinelPipelineTests.cs` — 1 new integration test |
| Modify | `README.md` — add SEC-29 row, bump count 44 → 45, mention `ExpectedResponseType` in config docs |
| Modify | `docs/BACKLOG.md` — remove "Output schema validation" row |
