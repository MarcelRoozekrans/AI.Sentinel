# Offline Replay + `sentinel` CLI Design

**Goal:** Ship `AI.Sentinel.Cli` — a `dotnet tool` that replays saved conversation JSON through the detector pipeline offline. Enables incident forensics and CI-style regression testing of detector changes against known-attack captures.

**Architecture:** Single new project `AI.Sentinel.Cli` (packed as `dotnet tool`) containing the replay library (`SentinelReplayClient`, `ConversationLoader`, `ReplayRunner`, `ReplayResult`) plus CLI entrypoint and output formatters. Main `AI.Sentinel` package is unchanged — no new dependencies.

**Tech Stack:** `Microsoft.Extensions.AI` (`IChatClient`, `ChatMessage`), `System.CommandLine` 2.0+ (CLI parsing), `System.Text.Json` (conversation and result serialization).

---

## Package structure

```
src/
├── AI.Sentinel/                 (unchanged)
├── AI.Sentinel.AspNetCore/      (unchanged)
└── AI.Sentinel.Cli/             (new)
```

**`AI.Sentinel.Cli`** targets `net8.0`, packed as:

```xml
<PropertyGroup>
  <PackAsTool>true</PackAsTool>
  <ToolCommandName>sentinel</ToolCommandName>
  <PackageId>AI.Sentinel.Cli</PackageId>
</PropertyGroup>
```

Depends on `AI.Sentinel` (project reference → package reference on publish) and `System.CommandLine` 2.0+.

The library classes (`SentinelReplayClient`, `ConversationLoader`, etc.) are `public` so callers wanting programmatic replay can reference `AI.Sentinel.Cli` like any library. If programmatic demand grows, we split later.

---

## `SentinelReplayClient`

Pre-loaded queue of assistant messages. Each `GetResponseAsync` call pops the next one.

```csharp
public sealed class SentinelReplayClient(IReadOnlyList<ChatMessage> recordedResponses) : IChatClient
{
    private int _index;

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken ct = default)
    {
        var next = Interlocked.Increment(ref _index) - 1;
        if (next >= recordedResponses.Count)
            throw new InvalidOperationException(
                $"Replay exhausted: {recordedResponses.Count} responses consumed.");
        return Task.FromResult(new ChatResponse([recordedResponses[next]]));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken ct = default)
        => throw new NotSupportedException("Use non-streaming GetResponseAsync for replay.");

    public ChatClientMetadata Metadata => new("replay", null, null);
    public object? GetService(Type serviceType, object? key = null) => null;
    public void Dispose() { }
}
```

---

## `ConversationLoader` + `ConversationFormat`

Two supported input formats: OpenAI Chat Completion JSON (`{"messages": [...]}`) and AI.Sentinel audit NDJSON (one JSON object per line, natively serialized `AuditEntry`).

```csharp
public enum ConversationFormat { Auto, OpenAIChatCompletion, AuditNdjson }

public sealed record LoadedConversation(
    IReadOnlyList<ConversationTurn> Turns);

public sealed record ConversationTurn(
    IReadOnlyList<ChatMessage> Prompt,
    ChatMessage Response);

public static class ConversationLoader
{
    public static async Task<LoadedConversation> LoadAsync(
        string path,
        ConversationFormat format = ConversationFormat.Auto,
        CancellationToken ct = default) { /* ... */ }
}
```

### Format handling

**OpenAI format**: walk the `messages` array, split on each `assistant` role. For turn N, prompt = messages before the Nth assistant message; response = that assistant message. This supports both single-turn and multi-turn conversations.

**Audit NDJSON**: one scan pass per line. Each line carries the full message list — turn reconstruction is trivial (last assistant message is the response; preceding messages are the prompt).

### Auto-detection

1. File extension `.ndjson` or `.jsonl` → NDJSON
2. Content starts with `{` and parses as a JSON object with a `messages` array at top level → OpenAI
3. Content is line-delimited and first line parses as a JSON object → NDJSON
4. Otherwise: throw with a clear message including the `--format` flag suggestion

---

## `ReplayResult` + `ReplayRunner`

Serializable detection output, one `TurnResult` per conversation turn.

```csharp
public sealed record ReplayResult(
    string SchemaVersion,
    string File,
    ConversationFormat Format,
    int TurnCount,
    IReadOnlyList<TurnResult> Turns,
    Severity MaxSeverity);

public sealed record TurnResult(
    int Index,
    Severity MaxSeverity,
    IReadOnlyList<TurnDetection> Detections);

public sealed record TurnDetection(
    string DetectorId,
    Severity Severity,
    string Reason);

public static class ReplayRunner
{
    public static async Task<ReplayResult> RunAsync(
        string file,
        LoadedConversation conversation,
        SentinelPipeline pipeline,
        CancellationToken ct = default) { /* ... */ }
}
```

`SchemaVersion` starts at `"1"`. Future breaking changes bump it; readers check compatibility.

---

## CLI surface

Single subcommand in v1. `System.CommandLine`-based.

```
sentinel scan <file>
  [--format <openai|audit|auto>]                      (default: auto)
  [--output <text|json>]                               (default: text)
  [--expect <detectorId>]                              (repeatable)
  [--min-severity <Low|Medium|High|Critical>]
  [--baseline <file>]
  [--config <sentinel.json>]
```

### Exit codes

- `0` — scan completed, assertions passed (or none specified)
- `1` — assertion failed: missing `--expect` detector, severity below `--min-severity`, or baseline regression
- `2` — I/O or parsing error (file not found, malformed JSON, auto-detect failed)

### Default `SentinelOptions` (no `--config`)

Forensics-oriented — all severities log only, never throw:

```csharp
var opts = new SentinelOptions
{
    OnCritical = SentinelAction.Log,
    OnHigh     = SentinelAction.Log,
    OnMedium   = SentinelAction.Log,
    OnLow      = SentinelAction.Log,
    EscalationClient = null,
    AuditCapacity = 10_000
};
```

LLM-escalation detectors (which require `EscalationClient`) are no-ops — the CLI never hits a real API.

### Text output

```
Scanned: conversation.json (openai, 3 turns)
───────────────────────────────────────────
Turn 1: Clean
Turn 2: HIGH
  SEC-01 PromptInjection: "ignore all previous instructions"
Turn 3: CRITICAL
  SEC-02 CredentialExposure: "password=abc..."
  HAL-01 PhantomCitation: "arxiv.org/abs/9999.99999"

Summary: 3 turns, 3 detections, max severity CRITICAL
```

### JSON output (and `--baseline` input format)

```json
{
  "schemaVersion": "1",
  "file": "conversation.json",
  "format": "openai",
  "turnCount": 3,
  "turns": [
    { "index": 0, "maxSeverity": "None", "detections": [] },
    { "index": 1, "maxSeverity": "High", "detections": [
      { "detectorId": "SEC-01", "severity": "High", "reason": "..." }
    ] }
  ],
  "maxSeverity": "Critical"
}
```

### Baseline diff (`--baseline prior.json`)

Load both `ReplayResult`s, compare turn-by-turn. For each turn:

- Detector in baseline but not current → **REGRESSION** (exit 1)
- Detector in current but not baseline → **NEW** (informational, exit 0 unless combined with assertions)
- Same detector but different severity → **CHANGED** (regression if current severity is lower)

Turn count mismatch → error (exit 2).

```
Baseline: prior.json (3 turns)
Current:  conversation.json (3 turns)
───────────────────────────────────────────
Turn 2: REGRESSION — SEC-01 no longer fires (was High)
Turn 3: NEW — HAL-01 now fires (High)
```

---

## Testing

### SentinelReplayClientTests

| Test | Verifies |
|---|---|
| `GetResponseAsync_ReturnsNextRecorded` | Successive calls pop in order |
| `GetResponseAsync_Exhausted_Throws` | `InvalidOperationException` past end |
| `GetStreamingResponseAsync_Throws` | Not supported |

### ConversationLoaderTests

| Test | Verifies |
|---|---|
| `LoadOpenAI_ValidMessagesArray_ReturnsTurns` | Parses `{"messages": [...]}` |
| `LoadOpenAI_SplitsOnAssistantRole` | Multi-turn → N turns |
| `LoadOpenAI_NoAssistantMessages_EmptyResult` | Prompt-only → zero turns |
| `LoadNdjson_OneLinePerTurn_ReturnsTurns` | Parses NDJSON audit format |
| `LoadAuto_OpenAIByContent_DetectsCorrectly` | Auto-detects OpenAI |
| `LoadAuto_NdjsonByExtension_DetectsCorrectly` | `.ndjson` → NDJSON |
| `LoadAuto_Ambiguous_Throws` | Clear error for unrecognizable input |

### ReplayRunnerTests

| Test | Verifies |
|---|---|
| `RunAsync_CleanConversation_AllTurnsClean` | No detections for benign input |
| `RunAsync_PromptInjection_Detected` | SEC-01 fires on injection |
| `RunAsync_MultipleTurns_IndependentResults` | Per-turn results isolated |

### ScanCommandTests

Using `System.CommandLine`'s in-memory test harness to run the command and capture exit codes / output.

| Test | Verifies |
|---|---|
| `Scan_CleanFile_ExitsZero` | Default scan |
| `Scan_WithExpectFlag_FiresExitsZero` | `--expect SEC-01` + match → 0 |
| `Scan_WithExpectFlag_MissingExitsOne` | `--expect SEC-01` + clean → 1 |
| `Scan_MinSeverityFail_ExitsOne` | `--min-severity High` + only Low → 1 |
| `Scan_OutputJson_EmitsSchemaV1` | Valid v1 schema JSON output |
| `Scan_BaselineRegression_ExitsOne` | Prior had SEC-01, current clean → 1 |
| `Scan_BaselineNewDetection_ExitsZero` | New detection only → 0 |
| `Scan_FileNotFound_ExitsTwo` | I/O error → 2 |
| `Scan_AutoDetectFails_ExitsTwo` | Format auto-detect fail → 2 |

### Fixtures

`tests/AI.Sentinel.Tests/Fixtures/conversations/`:
- `clean-openai.json` — benign conversation
- `injection-openai.json` — known SEC-01 attack
- `multi-turn.ndjson` — two audit entries
- `baseline-prior.json` — serialized `ReplayResult`

---

## Files changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel.Cli/AI.Sentinel.Cli.csproj` |
| New | `src/AI.Sentinel.Cli/Program.cs` |
| New | `src/AI.Sentinel.Cli/SentinelReplayClient.cs` |
| New | `src/AI.Sentinel.Cli/ConversationLoader.cs` |
| New | `src/AI.Sentinel.Cli/ConversationFormat.cs` |
| New | `src/AI.Sentinel.Cli/ReplayRunner.cs` |
| New | `src/AI.Sentinel.Cli/ReplayResult.cs` |
| New | `src/AI.Sentinel.Cli/ScanCommand.cs` |
| New | `src/AI.Sentinel.Cli/TextFormatter.cs` |
| New | `src/AI.Sentinel.Cli/JsonFormatter.cs` |
| New | `src/AI.Sentinel.Cli/BaselineDiffer.cs` |
| New | `src/AI.Sentinel.Cli/AssertionEvaluator.cs` |
| Modify | `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` — add CLI project reference |
| New | `tests/AI.Sentinel.Tests/Replay/SentinelReplayClientTests.cs` |
| New | `tests/AI.Sentinel.Tests/Replay/ConversationLoaderTests.cs` |
| New | `tests/AI.Sentinel.Tests/Replay/ReplayRunnerTests.cs` |
| New | `tests/AI.Sentinel.Tests/Cli/ScanCommandTests.cs` |
| New | `tests/AI.Sentinel.Tests/Fixtures/conversations/*.json` |
| Modify | `README.md` — add CLI installation + usage section |
| Modify | `docs/BACKLOG.md` — remove "Offline replay" + "sentinel CLI tool" rows |
