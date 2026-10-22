# Hook and MCP Proxy Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tool results, prompts and resources that flow toward the model through the MCP proxy, the Claude Code hook CLI and the Copilot hook CLI are redacted wherever the host lets them be rewritten. The proxy restores PII it minted into later tool-call arguments. Every host without a rewrite keeps the 3.0 fallback: the severity action and `; not redacted`.

**Architecture:**
- One new internal `SentinelPipeline.RedactAndScanAsync` takes host content as text or JSON. It redacts the content with a per-call `RedactionSession`, redacts the request context in a scan copy only, and scans with the placeholders exempt. It writes `REDACTED` entries for the content only. On any redaction failure it falls back to the 3.0 scan.
- The MCP interceptors rewrite results in place. A proxy-scoped `PlaceholderStore` collects what each call minted and restores PII into later `tools/call` arguments.
- The hook adapters return the redacted payload on the additive `HookOutput.UpdatedToolOutput`. Each CLI maps `HookOutput` to its host's documented wire JSON. For Claude Code that fixes the undocumented `{"decision":"Allow"}` output.

**Tech Stack:** .NET 8/9/10, Microsoft.Extensions.AI 10.11, ModelContextProtocol 2.3, System.Text.Json source generation, xunit.v3.

**Spec:** `docs/superpowers/specs/2026-10-21-hook-mcp-redaction-design.md`

## Global Constraints

- Warnings as errors. Analyzers run as errors, including ZA0601, which forbids LINQ inside loops in tests too. Fix the code, never suppress.
- AOT/trim clean: no reflection-based JSON. Every new serialized type goes through a source-generated `JsonSerializerContext`. Build a JSON string element with `Utf8JsonWriter` and `JsonDocument`, never `JsonSerializer.SerializeToElement(object)`.
- `dotnet format whitespace . --folder --verify-no-changes` passes before every commit.
- No breaking change, only additive init members and enum values. `HookOutput`, `HookInput`, `HookConfig`, `CopilotHookInput`, `CopilotHookConfig` and `CopilotHookEvent` gain members only. Existing pinned JSON for `HookOutput`, `HookInput` and `CopilotHookInput` serialization stays byte-identical. New members carry `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`.
- Commit messages with no nested parentheses and no body line starting `word:`.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No `claude.ai/code/session_*` link in any commit or PR body.
- Branch `feat/hook-mcp-redaction` from a freshly fetched `origin/main`. One PR closing #364, with `feat`/`fix` commits only and no `!`, so release-please opens 3.1.0.
- No original value may reach an `AuditEntry`, a log or stderr line, an exception message, `HookOutput.Reason`, `ToString()` or the placeholder guard's reason.
- Withheld body, exact: `withheld by AI.Sentinel: <reason>`, where `<reason>` is `HookOutput.Reason`.
- Env switches `SENTINEL_HOOK_REDACT` and `SENTINEL_MCP_REDACT`: `on`, `1`, `true` or `yes` turn redaction on, and `off`, `0`, `false` or `no` turn it off. Anything else keeps the default, which is on. `SENTINEL_MCP_REDACT` falls back to `SENTINEL_HOOK_REDACT`.
- `SENTINEL_MCP_REDACT_TTL_MIN` is a positive integer number of minutes; default 30, and anything else keeps 30. The store's size cap is `PlaceholderStore.DefaultMaxEntries = 10_000`.
- Run one class with `dotnet test tests/AI.Sentinel.Tests -- --filter-class "*<Name>*"`. Run the full `dotnet test` before the push.

## Review Focus

1. **A built-in tool's structured `tool_response`,** such as Claude Code `Read` returning `{"type":"text","file":{"filePath":"/a/.env","content":"...","numLines":3}}`. A person expects the same keys, numbers and nesting back, with only string leaves changed; otherwise Claude Code ignores the rewrite. Pinned in Task 5 by `PostToolUse_ReadResponse_KeepsShape_OnlyStringLeavesChange`.
2. **A tool result that echoes a placeholder from an earlier proxy call,** for example a search tool that returns its query. It is expected to pass with no finding and no block, and to stay restorable. Pinned in Task 3 by `ToolResult_EchoingEarlierPlaceholder_IsNotBlocked`.
3. **A placeholder used after its idle expiry, or after eviction.** It is expected to reach the tool as literal text, with no error and no other value substituted. Pinned in Task 1 by `Restore_AfterIdleExpiry_LeavesTokenLiteral` and `Register_OverCap_EvictsLeastRecentlyUsed`, and end to end in Task 3 by `ExpiredPlaceholder_ReachesToolLiteral`.
4. **Copilot sending `toolArgs` as a JSON string rather than an object.** The reference types it `unknown`, so a person expects the scan and the placeholder guard to see it either way. Pinned in Task 4 by `PreToolUse_ToolArgsAsJsonString_IsScanned` and in Task 6 by `CopilotGuard_ToolArgsAsJsonString_Denies`.
5. **One value in both the arguments and the result.** It is expected to be counted once in the `REDACTED` entry, for the result only, because the arguments are redacted in the scan copy alone. Pinned in Task 1 by `ValueInContextAndContent_CountedOnceForContent`.

---

### Task 1: The shared redacting path and the proxy-scoped placeholder store

**Files:**
- Create: `src/AI.Sentinel/Redaction/HostRedaction.cs`, holding `HostContent`, `HostRedactionRequest` and `HostRedactionResult`
- Create: `src/AI.Sentinel/Redaction/MintedPlaceholder.cs`
- Create: `src/AI.Sentinel/Redaction/PlaceholderStore.cs`
- Modify: `src/AI.Sentinel/Redaction/RedactionSession.cs`: add the export and the values-only JSON walk next to `MapJson`/`WriteMapped`, lines 817-861
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`: `ScanMessagesCoreAsync`, lines 488-503, takes exemptions; `AppendRedactionsAsync`, lines 371-393, gets a counts overload; add the new method next to `ScanMessagesForFindingsAsync`
- Test: `tests/AI.Sentinel.Tests/Redaction/HostRedactionTests.cs`, `tests/AI.Sentinel.Tests/Redaction/PlaceholderStoreTests.cs`

**Interfaces:**
- Consumes: `RedactionSession`, `RedactionScope.ExemptPlaceholders(RedactionSession?, RedactionScope?)`, `ScanFinding(DetectionResult Detection, SentinelAction Action)`, `AuditEntryRedactionExtensions.Redaction`, and `PlaceholderFormat.Pattern()`.
- Produces, all `internal` in namespace `AI.Sentinel.Redaction` unless noted:
  - `readonly record struct MintedPlaceholder(string Token, string Value, bool RestoreIntoToolArguments)`. It overrides `ToString()` to return `Token` only.
  - `RedactionSession.ExportMinted() -> IReadOnlyList<MintedPlaceholder>`. It is a snapshot taken under the lock, and `RestoreIntoToolArguments` is true when the token is in `_toolRestorable`.
  - `RedactionSession.RedactJsonValues(JsonElement element) -> JsonElement`. It redacts string values only. Property names, numbers, booleans, nulls and the nesting are written unchanged.
  - `readonly record struct HostContent` with `string? Text`, `JsonElement? Json` and the factories `static HostContent FromText(string text)` and `static HostContent FromJson(JsonElement json)`. Exactly one of the two members is set.
  - `sealed record HostRedactionRequest` with:
    - `IReadOnlyList<ChatMessage> Context { get; init; } = []`: request context, redacted in the scan copy only;
    - `required IReadOnlyList<HostContent> Content { get; init; }`: what goes toward the model;
    - `ChatRole ContentRole { get; init; } = ChatRole.Assistant`;
    - `IReadOnlyList<ChatMessage> Unredactable { get; init; } = []`: scanned verbatim, for oversize blocks;
    - `IReadOnlySet<string>? KnownPlaceholders { get; init; }`: placeholders from earlier calls that the scan must not flag.
  - `sealed record HostRedactionResult(IReadOnlyList<HostContent> Content, IReadOnlyList<ScanFinding> Findings, SentinelError? Error, IReadOnlyDictionary<string, int> RedactedByType, IReadOnlyList<MintedPlaceholder> Minted, bool FellBack)`, with `bool Redacted => RedactedByType.Count > 0`. `Content` has the same count and order as the request's.
  - On `AI.Sentinel.SentinelPipeline`: `internal ValueTask<HostRedactionResult> RedactAndScanAsync(HostRedactionRequest request, SessionId? sessionId, CancellationToken ct)`.
  - On `AI.Sentinel.SentinelPipeline`: `internal ValueTask<SentinelError?> ScanMessagesExemptingAsync(IEnumerable<ChatMessage> messages, SessionId? sessionId, IReadOnlySet<string>? exemptPlaceholders, CancellationToken ct)`, for the MCP request scan in Task 3.
  - `sealed class PlaceholderStore`, thread-safe:
    - `const int DefaultMaxEntries = 10_000`;
    - `static TimeSpan DefaultIdleExpiry { get; } = TimeSpan.FromMinutes(30)`;
    - `PlaceholderStore(TimeSpan idleExpiry, int maxEntries = DefaultMaxEntries, TimeProvider? timeProvider = null)`;
    - `int Count { get; }`;
    - `void Register(IReadOnlyList<MintedPlaceholder> minted)`;
    - `IReadOnlySet<string> KnownTokens()`;
    - `string RestoreToolArgument(string text)`;
    - `IDictionary<string, JsonElement>? RestoreToolArguments(IDictionary<string, JsonElement>? arguments)`;
    - `override string ToString() => nameof(PlaceholderStore)`.

- [ ] **Step 1: Write the failing tests** in `HostRedactionTests`. Build the pipeline with `new ServiceCollection().AddAISentinel(o => { o.OnMedium = SentinelAction.Quarantine; o.OnHigh = SentinelAction.Quarantine; o.OnCritical = SentinelAction.Quarantine; })`, then `provider.BuildSentinelPipeline(client)`, and read entries from the provider's `IAuditStore`. Use `Email = "jan@example.com"` and `ApiKey = "api_key=sk-test-0123456789abcdefghij"`.
  - `TextContent_WithEmail_ReturnsPlaceholder_AndNoFinding`: `Content = [FromText($"mail {Email}")]`. Assert that `result.Content[0].Text` matches `Placeholders.Untag(...) == "mail [EMAIL_1]"`, that `result.Findings` is empty and `result.Error` is null, that `result.RedactedByType["EMAIL"] == 1`, and that `FellBack` is false.
  - `JsonContent_KeepsShape_RedactsStringValuesOnly`: the input is `{"user":"jan@example.com","n":3,"ok":true,"jan@example.com":null}`. Assert the output parses with the same property names, including the email-named key unchanged, `n == 3` and `ok == true`, and the `user` value matches `[EMAIL_1_*]`.
  - `RedactedContent_WritesOneRedactedEntry_CountsOnly`: assert one entry with `PolicyCode == "REDACTED"`, `Severity == Severity.None` and `Summary == "Redacted 1 EMAIL"`, and that no entry summary contains `Email`.
  - `ValueInContextAndContent_CountedOnceForContent`: `Context = [new(ChatRole.User, $"tool:x input:{{\"to\":\"{Email}\"}}")]` and Content holds the same email once. Assert `Summary == "Redacted 1 EMAIL"` and that no finding has `DetectorId` `SEC-23`.
  - `SecretInContent_MintedAsNotToolRestorable`: assert `result.Minted` has one `API_KEY` token with `RestoreIntoToolArguments == false`, and an `EMAIL` token is `true`.
  - `RedactorThrows_FallsBack_SeverityActionAndNotRedacted`: use a throwing `IRedactingDetector` registered with `Action = Redact` beside `PiiLeakageDetector`. Assert `FellBack`, that `Content` is the input unchanged, that `Error` is `SentinelError.ThreatDetected`, and that an audit summary ends with `; not redacted`.
  - `KnownPlaceholders_AreExempt`: with `KnownPlaceholders = {"[API_KEY_1_k3f9x2]"}` and Content `api_key=[API_KEY_1_k3f9x2]`, assert that `Findings` is empty.
  - `NoRedactors_ScansUnchanged`: with `RedactByDefault = false`, assert that `Content` is unchanged, that `Redacted` is false, and that the email yields a SEC-23 finding.
- [ ] **Step 2: Write the failing tests** in `PlaceholderStoreTests`, using a private `ManualClock : TimeProvider`.
  - `Restore_PiiToken_RestoresValue_SecretTokenStaysLiteral`.
  - `Restore_TokensFromTwoSessions_BothRestore`: two `RedactionSession`s with different tags, each registered.
  - `Restore_UnknownToken_StaysLiteral`.
  - `Restore_AfterIdleExpiry_LeavesTokenLiteral`: advance 31 minutes with a 30-minute expiry, then assert that `Count == 0` after the call.
  - `Restore_RefreshesIdleTimer`: restore at 20 minutes, then again at 40, and the second still restores.
  - `Register_OverCap_EvictsLeastRecentlyUsed`: `maxEntries: 2`, register A, B and C, and assert that A stays literal while B and C restore.
  - `RestoreToolArguments_WalksNestedJson_KeysUnchanged_InputNotMutated`.
  - `RestoreToolArguments_NothingToRestore_ReturnsSameInstance`.
  - `ToString_NeverPrintsValues`: covers `PlaceholderStore` and `MintedPlaceholder`.
  - `ConcurrentRegisterAndRestore_NoException`: 8 parallel tasks × 500 operations.
- [ ] **Step 3: Run them.** `dotnet test tests/AI.Sentinel.Tests -- --filter-class "*HostRedactionTests*"` and `"*PlaceholderStoreTests*"`. Expected: they do not compile, because the types are missing.
- [ ] **Step 4: Implement** the Interfaces above.
  - **`RedactAndScanAsync` order.**
    1. Take a new `RedactionSession(pipeline.Redactors)`. When it is empty, scan `Context + Content + Unredactable` verbatim through `ScanMessagesCoreAsync`, with no audit of redactions.
    2. Redact each Content item: `Redact` for text, `RedactJsonValues` for JSON.
    3. Snapshot `CountsByDetector` and `ExportMinted()`.
    4. Redact `Context` with `RedactRequest` into a scan copy.
    5. Scan the redacted context, then one `ContentRole` message per content item (text, or the JSON raw text), then `Unredactable`. Exempt `ExemptPlaceholders(session, null)` united with `KnownPlaceholders`, and collect findings.
    6. Append redactions from the step-3 snapshot through a new `AppendRedactionsAsync(IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> byDetector, SessionId, CancellationToken)` overload. The existing session overload delegates to it.
  - **Fallback.** Any exception except `OperationCanceledException` from steps 1-4 discards the session and runs the 3.0 scan verbatim with `FellBack = true`. Do not chain the exception.
  - **`PlaceholderStore`.** Purge expired entries lazily on each call. A restore refreshes the entry's last use. Eviction drops the least recently used entry. Only `RestoreIntoToolArguments` entries restore.
- [ ] **Step 5: Run both classes.** Expected: PASS. Then run `--filter-class "*Redaction*"` to confirm that the 3.0 redaction tests still pass.
- [ ] **Step 6: Commit.**

```bash
git add src/AI.Sentinel/Redaction src/AI.Sentinel/SentinelPipeline.cs tests/AI.Sentinel.Tests/Redaction
git commit -m "feat(redaction): add a redacting scan path for host content and a placeholder store

Hosts such as the MCP proxy and the hook CLIs hand Sentinel text or JSON
instead of chat messages. The new internal path redacts that content, scans
the redacted copy with its placeholders exempt and audits counts for the
content only. A redaction failure falls back to the 3.0 scan.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: MCP proxy redacts tool results, prompts and resources

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode/HookConfig.cs`: add the property and read it in `FromEnvironment`, lines 40-55
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs`: `Create` and `InvokeAsync`, lines 38-92
- Modify: `src/AI.Sentinel.Mcp/PromptGetInterceptor.cs`, lines 24-75
- Modify: `src/AI.Sentinel.Mcp/ResourceReadInterceptor.cs`, lines 138-209; make `ParseMimeAllowlist` internal
- Modify: `src/AI.Sentinel.Mcp/MessageBuilder.cs`: add the content extraction
- Modify: `src/AI.Sentinel.Mcp/McpProxy.cs`: `RunAsync`, `RunWithSessionAsync` and the `Wire*` methods, lines 51-160 and 225-348
- Test: `tests/AI.Sentinel.Tests/Mcp/McpRedactionTests.cs`, and extend `tests/AI.Sentinel.Tests/ClaudeCode/HookAdapterTests.cs` for the config switch

**Interfaces:**
- Consumes: Task 1's `RedactAndScanAsync`, `HostContent`, `HostRedactionRequest`, `HostRedactionResult` and `PlaceholderStore`.
- Produces:
  - `HookConfig.RedactToolResults { get; init; } = true`, public, read from `SENTINEL_HOOK_REDACT` by a new private `ParseOnByDefault(env, key)`.
  - `ToolCallInterceptor.Create(..., SessionId? sessionId = null, PlaceholderStore? placeholders = null)`. Null means 3.0 behaviour.
  - `PromptGetInterceptor.Create(SentinelPipeline pipeline, int maxScanBytes, TextWriter stderr, SessionId? sessionId = null, PlaceholderStore? placeholders = null)`.
  - `ResourceReadInterceptor.Create(SentinelPipeline pipeline, SessionId? sessionId = null, PlaceholderStore? placeholders = null)`.
  - `McpProxy.RunAsync(..., IReadOnlyList<IAuditForwarder>? forwarders = null, TimeSpan? placeholderIdleExpiry = null)` and the same trailing parameter on `RunWithSessionAsync`. When `config.RedactToolResults` is set, the proxy builds one `PlaceholderStore(placeholderIdleExpiry ?? PlaceholderStore.DefaultIdleExpiry)` per run and passes it to all three interceptors.
  - `internal static ResourceReadInterceptor.ParseMimeAllowlist() -> HashSet<string>`.

- [ ] **Step 1: Write the failing tests** in `McpRedactionTests`. Drive the filters directly, as `McpAuditTests` does, with `RuntimeHelpers.GetUninitializedObject` for `RequestContext<T>`. Build the pipeline with `McpPipelineFactory.Assemble(options, [new PiiLeakageDetector(), new CredentialExposureDetector()], store)`, where every severity maps to `Warn`.
  - `ToolResult_TextBlock_EmailBecomesPlaceholder`: assert that the returned `TextContentBlock.Text` matches `[EMAIL_1_*]` and no longer contains the email.
  - `ToolResult_EmbeddedTextResource_Redacted`: `EmbeddedResourceBlock { Resource = new TextResourceContents { MimeType = "text/plain", Text = email } }`.
  - `ToolResult_StructuredContent_RedactedLeafByLeaf_ShapeKept`.
  - `ToolResult_ImageBlockAndBlobResource_Untouched`.
  - `ToolResult_OversizeBlock_NotRedacted_FallsBackWithNotRedactedSuffix`: `maxScanBytes: 64` and a 200-byte text holding an email. Assert that the text is unchanged and an audit summary ends with `; not redacted`.
  - `ToolResult_Redaction_WritesRedactedEntryWithSessionId`.
  - `ToolResult_InjectionAfterRedaction_StillBlocks`: map Critical to Block and use `PromptInjectionDetector`, which throws `McpProtocolException`.
  - `PromptGet_MessageTextAndEmbeddedResource_Redacted`.
  - `ResourceRead_AllowlistedText_Redacted_NonAllowlistedUntouched`.
  - `NullStore_BehavesAsThreeZero`: with `placeholders: null`, the email stays and the summary ends with `; not redacted`.
  - In `HookAdapterTests`: `HookConfig_FromEnvironment_RedactSwitch` is a theory over `("off", false)`, `("0", false)`, `("on", true)`, `("garbage", true)` and `(null, true)`.
- [ ] **Step 2: Run** `--filter-class "*McpRedactionTests*"`. Expected: FAIL, because the parameters and the property are missing.
- [ ] **Step 3: Implement.**
  - **Content extraction.** Add `MessageBuilder.CollectRedactable(IList<ContentBlock>? blocks, JsonElement? structured, int maxScanBytes, HashSet<string> allowedMimes) -> (List<HostContent> Content, List<Action<HostContent>> Apply, List<ChatMessage> Oversize)`. Each `Apply[i]` writes `Content[i]` back:
    - into the `TextContentBlock.Text`;
    - into the `TextResourceContents.Text`, for an allowlisted MIME;
    - into `CallToolResult.StructuredContent`.
  - **Size limit.** An item whose UTF-8 size exceeds `maxScanBytes` goes to `Oversize` as `TruncateIfNeeded` text instead.
  - **Rewrite.** The interceptors mutate the result returned by `next` in place. It is freshly deserialized per request.
  - **Context.** In `ToolCallInterceptor`, the context is `BuildToolCallRequest(req, maxScanBytes)`.
  - **Block and log.** A `HostRedactionResult.Error` of type `ThreatDetected` goes through the existing `BlockIfThreatAsync`. Append ` redacted=<total count>` to the Allow stderr line when `Redacted` is true.
  - **Store.** Every interceptor calls `placeholders.Register(result.Minted)` and passes `placeholders.KnownTokens()` as `KnownPlaceholders`.
- [ ] **Step 4: Run** `--filter-class "*McpRedactionTests*"`, `"*McpProxyTests*"`, `"*McpAuditTests*"`, `"*ResourceReadInterceptorTests*"` and `"*HookAdapterTests*"`. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.ClaudeCode/HookConfig.cs src/AI.Sentinel.Mcp tests/AI.Sentinel.Tests/Mcp tests/AI.Sentinel.Tests/ClaudeCode/HookAdapterTests.cs
git commit -m "feat(mcp): redact tool results, prompts and resources in the proxy

Text blocks, embedded text resources and structured content get placeholders
before they reach the agent. Blob, non-allowlisted and oversize content keeps
the 3.0 fallback.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: MCP restore into tool-call arguments, plus the env vars

**Files:**
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs`: `InvokeAsync` and `ScanSafelyAsync`, lines 55-92 and 219-238
- Modify: `src/AI.Sentinel.Mcp.Cli/ProxyCommand.cs`: `ResolveHookConfig`, lines 179-190; add a TTL parser beside `ParseMaxScanBytes`, lines 216-223; pass it through `RunProxyAsync`, lines 120-160
- Test: extend `tests/AI.Sentinel.Tests/Mcp/McpRedactionTests.cs`; add `tests/AI.Sentinel.Tests/Mcp/McpRedactionProxyTests.cs`; extend `tests/AI.Sentinel.Tests/Mcp/McpCliTests.cs`

**Interfaces:**
- Consumes: `PlaceholderStore.RestoreToolArguments`, `PlaceholderStore.KnownTokens()`, `SentinelPipeline.ScanMessagesExemptingAsync`, `HookConfig.RedactToolResults`, `ProxyCommand.ParseSwitch`, and `McpProxy.RunAsync(..., placeholderIdleExpiry)`.
- Produces: `internal static TimeSpan ProxyCommand.ParseRedactionIdleExpiry(IReadOnlyDictionary<string, string?> env)`. `ResolveHookConfig` sets `RedactToolResults = ParseSwitch(envVars, "SENTINEL_MCP_REDACT") ?? envBaseline.RedactToolResults`.

- [ ] **Step 1: Write the failing tests.**
  - In `McpRedactionProxyTests`, run the full proxy against `FakeMcpServer` with `preset: McpDetectorPreset.All` and every severity mapped to `Warn`.
    - `LookupThenAct_PiiRestored_SecretNot`: the first `read_file` result holds an email and `api_key=sk-test-0123456789abcdefghij`. The agent sees the two placeholders and calls `send` with both. Assert that `Fake.ReceivedToolCalls[1].Arguments` holds the real email and the `[API_KEY_1_*]` placeholder.
    - `ToolResult_EchoingEarlierPlaceholder_IsNotBlocked`: map every severity to Block. The second result echoes the first call's `[EMAIL_1_*]`. Assert no exception, and that the token is returned unchanged.
    - `ExpiredPlaceholder_ReachesToolLiteral`: use `placeholderIdleExpiry: TimeSpan.FromMilliseconds(1)` and wait 50 ms through `Task.Delay`. Assert that the placeholder reaches the fake unchanged.
    - `RedactOff_ArgumentsAndResultsUntouched`: with `RedactToolResults = false`, assert the email reaches the driver.
  - In `McpRedactionTests`:
    - `Guard_SeesRestoredArguments`: a recording `IToolCallGuard` receives the real email.
    - `RequestScan_JudgesArgumentsAsSent_PlaceholderExempt`: map every severity to Block. A restored email in the arguments does not block.
  - In `McpCliTests`:
    - `ResolveHookConfig_McpRedactOverridesHookRedact` is a theory over `(mcp "off", hook "on") → false`, `(mcp null, hook "off") → false` and `(both null) → true`.
    - `ParseRedactionIdleExpiry` is a theory over `"5" → 5 min`, `"0" → 30`, `"x" → 30` and `null → 30`.
- [ ] **Step 2: Run** `--filter-class "*McpRedaction*"` and `"*McpCliTests*"`. Expected: FAIL.
- [ ] **Step 3: Implement** in `ToolCallInterceptor.InvokeAsync`.
  1. Compute `restored = placeholders?.RestoreToolArguments(req.Arguments)`.
  2. Authorize with the restored arguments.
  3. Pre-scan `BuildToolCallRequest` over the arguments as the agent sent them, through `ScanMessagesExemptingAsync` with `placeholders.KnownTokens()`.
  4. Set `ctx.Params = req with restored arguments`. `CallToolRequestParams.Arguments` is settable, so build a new `CallToolRequestParams { Name, Arguments = restored, Meta = req.Meta }` instead of mutating `req`.
  5. Call `next`.

  The response context uses the arguments as sent. Wire the TTL through `RunProxyAsync` into `McpProxy.RunAsync`.
- [ ] **Step 4: Run** the step 2 classes and `"*McpProxyTests*"`. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.Mcp src/AI.Sentinel.Mcp.Cli tests/AI.Sentinel.Tests/Mcp
git commit -m "feat(mcp): restore PII placeholders into later tool calls

The proxy keeps the placeholders it minted for its lifetime, with an idle
expiry set by SENTINEL_MCP_REDACT_TTL_MIN. PII placeholders in later
tools/call arguments are restored before the tool runs; secrets never are.
SENTINEL_MCP_REDACT turns redaction off, falling back to SENTINEL_HOOK_REDACT.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Copilot input field names

**Files:**
- Modify: `src/AI.Sentinel.Copilot/CopilotHookInput.cs`
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs`: the authorization block, lines 67-72, and `BuildMessages`
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/HookWireFormatTests.cs`, `tests/AI.Sentinel.Tests/Copilot/CopilotHookAdapterTests.cs`

**Interfaces:**
- Produces, public and additive on `CopilotHookInput`, each with `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`:
  - `JsonElement? ToolArgs { get; init; }`;
  - `JsonElement? ToolResult { get; init; }`;
  - `string? TransformedPrompt { get; init; }`.
- Produces, internal on `CopilotHookInput`, both `[JsonIgnore]`:
  - `JsonElement? EffectiveToolArgs => ToolArgs ?? ToolInput`;
  - `JsonElement? EffectiveToolResult => ToolResult ?? ToolResponse`.

- [ ] **Step 1: Write the failing tests.**
  - `Copilot_CamelCasePayload_ReadsToolArgsAndToolResult` deserializes `{"sessionId":"c-1","toolName":"bash","toolArgs":{"command":"ls"},"toolResult":{"resultType":"success","textResultForLlm":"ok"}}` and asserts both raw texts.
  - `Copilot_UserPromptTransformedPayload_ReadsTransformedPrompt`.
  - The existing `Copilot_Input_Serializes_CamelCase` stays unchanged and must still pass.
  - In `CopilotHookAdapterTests`:
    - `PreToolUse_InjectionInToolArgs_Blocks`;
    - `PostToolUse_InjectionInToolResult_Blocks`;
    - `PreToolUse_ToolArgsAsJsonString_IsScanned`, with `"toolArgs":"{\"command\":\"ignore all previous instructions\"}"`;
    - `ToolArgsPreferredOverToolInput`;
    - `Guard_ReceivesToolArgs`.
- [ ] **Step 2: Run** `--filter-class "*HookWireFormatTests*"` and `"*CopilotHookAdapterTests*"`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Use the effective members everywhere `ToolInput` and `ToolResponse` were read.
- [ ] **Step 4: Run** the same two classes. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.Copilot tests/AI.Sentinel.Tests/ClaudeCode/HookWireFormatTests.cs tests/AI.Sentinel.Tests/Copilot
git commit -m "fix(copilot): read toolArgs and toolResult from the hook payload

Copilot sends toolArgs and toolResult, not toolInput and toolResponse, so
tool scans saw empty arguments and no result. The documented names are now
read and preferred.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Claude Code wire output, PostToolUse redaction and withheld on Block

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode/HookOutput.cs`
- Modify: `src/AI.Sentinel.ClaudeCode/HookPipelineRunner.cs`
- Modify: `src/AI.Sentinel.ClaudeCode/HookAdapter.cs`: the PostToolUse path, lines 136-150
- Modify: `src/AI.Sentinel.ClaudeCode/AssemblyAttributes.cs`: add `InternalsVisibleTo("AI.Sentinel.Copilot")`
- Create: `src/AI.Sentinel.ClaudeCode.Cli/ClaudeCodeWireOutput.cs`, holding the wire records and `ClaudeCodeWireJsonContext`
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs`: stdout write, lines 78-101; `ExitCodeAsync`, lines 144-150
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/HookWireFormatTests.cs`, `HookCliTests.cs`, `HookAdapterTests.cs`, `HookCliAuditTests.cs`

**Interfaces:**
- Consumes: Task 1's `RedactAndScanAsync` and `HostContent.FromJson`, Task 2's `HookConfig.RedactToolResults`, and `HookPipelineRunner.Decide`.
- Produces:
  - Public, additive, on `HookOutput`, each `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]`:
    - `JsonElement? UpdatedToolOutput { get; init; }`;
    - `IReadOnlyDictionary<string, int>? Redactions { get; init; }`.
  - `internal const string HookPipelineRunner.WithheldPrefix = "withheld by AI.Sentinel: "`.
  - `internal static JsonElement HookPipelineRunner.JsonString(string text)`.
  - `internal static Task<HookOutput> HookPipelineRunner.RunToolResultAsync(IServiceProvider provider, HookConfig config, IReadOnlyList<ChatMessage> context, JsonElement toolResult, string? sessionId, CancellationToken ct)`. A Block gets `UpdatedToolOutput = JsonString(WithheldPrefix + Reason)`. A redaction without a Block gets the redacted JSON and `Redactions = RedactedByType`. A fallback or clean result leaves both null.
  - In `AI.Sentinel.ClaudeCode.Cli`, all internal:
    - `sealed record ClaudeCodeWireOutput { string? Decision; string? Reason; string? SystemMessage; ClaudeCodeHookSpecificOutput? HookSpecificOutput; static ClaudeCodeWireOutput? From(HookEvent evt, HookOutput output); }`;
    - `sealed record ClaudeCodeHookSpecificOutput { required string HookEventName; JsonElement? UpdatedToolOutput; string? AdditionalContext; }`;
    - `ClaudeCodeWireJsonContext`, with camelCase naming and `DefaultIgnoreCondition = WhenWritingNull`.

- [ ] **Step 1: Write the failing tests.** These tests re-pin the CLI's stdout. That is the spec's bug fix. The `HookOutput` serialization pins stay.
  - Wire tests in `HookWireFormatTests`:
    - `ClaudeCodeWire_Allow_IsEmptyObject`: `From(PreToolUse, Allow)` serializes to `{}`.
    - `ClaudeCodeWire_Warn_IsSystemMessage`: the reason `r` gives `{"systemMessage":"AI.Sentinel: r"}`.
    - `ClaudeCodeWire_PreToolUseBlock_IsNull`: no stdout, because exit 2 and stderr carry it.
    - `ClaudeCodeWire_PostToolUseRedacted`: `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{...},"additionalContext":"AI.Sentinel redacted 1 EMAIL in this tool output. Placeholders such as [EMAIL_1_k3f9x2] stand for the real values; do not write them to files or commands."}}`. The type list is ordinal, comma-separated: `1 API_KEY, 1 EMAIL`.
    - `ClaudeCodeWire_PostToolUseBlock_WithholdsOutput`: `{"decision":"block","reason":"r","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"withheld by AI.Sentinel: r","additionalContext":"r"}}`.
    - `HookOutput_NewMembersNull_PinnedJsonUnchanged`: the existing `{"decision":"Allow","reason":null}` pin.
  - Adapter tests in `HookAdapterTests`:
    - `PostToolUse_EmailInResponse_UpdatedToolOutputHasPlaceholder`;
    - `PostToolUse_ReadResponse_KeepsShape_OnlyStringLeavesChange`, over the Review Focus 1 payload;
    - `PostToolUse_InjectionInResponse_BlockWithWithheldBody`;
    - `PostToolUse_RedactOff_NoUpdatedToolOutput_NotRedactedSuffix`;
    - `PreToolUse_EmailInInput_NotRedacted_FallsBack`, because arguments are a non-goal.
  - CLI tests in `HookCliTests`:
    - `Cli_PostToolUse_Email_ExitZero_StdoutCarriesPlaceholder`;
    - `Cli_PostToolUse_Injection_ExitZero_Withheld`;
    - `Cli_CleanPrompt_StdoutIsEmptyObject`;
    - `Cli_InjectionPrompt_ExitsTwo_StdoutEmpty`.
    - Re-pin `Cli_ComplianceFinding_WarnsInsteadOfBlocking` to assert `CMP-03` in `stdout`'s `systemMessage` and not in stderr.
  - Audit tests in `HookCliAuditTests`: `PostToolUseRedaction_RecordedAsRedactedWithClaudeCodeSource`.
- [ ] **Step 2: Run** `--filter-class "*HookWireFormatTests*"`, `"*HookAdapterTests*"`, `"*HookCliTests*"` and `"*HookCliAuditTests*"`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.**
  - **Adapter.** `HookAdapter` routes PostToolUse with a `ToolResponse` and `RedactToolResults` through `RunToolResultAsync`. Every other event keeps `RunAsync`.
  - **Program stdout.** Write `ClaudeCodeWireOutput.From(evt, output)` through `ClaudeCodeWireJsonContext`, and write nothing when it is null.
  - **Exit codes.** `ExitCodeAsync` takes the event:
    - Block on PreToolUse or UserPromptSubmit: exit 2, reason on stderr;
    - Block on PostToolUse: exit 0, nothing on stderr;
    - Warn: exit 0, nothing on stderr;
    - Allow: exit 0.
  - **Comment.** Update the comment at Program line 89 to say that only Block puts the reason on stderr.
- [ ] **Step 4: Run** the step 2 classes. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.ClaudeCode src/AI.Sentinel.ClaudeCode.Cli tests/AI.Sentinel.Tests/ClaudeCode
git commit -m "fix(claude-code): write documented hook output and redact tool results

sentinel-hook wrote decision Allow and Warn, which Claude Code does not
accept. It now writes an empty object, a systemMessage for a warning, or
hookSpecificOutput. PostToolUse replaces the tool output with a redacted
copy, and a block withholds it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: PreToolUse placeholder guard on both hosts

**Files:**
- Create: `src/AI.Sentinel.ClaudeCode/PlaceholderGuard.cs`
- Modify: `src/AI.Sentinel.ClaudeCode/HookAdapter.cs`: after the authorization block, before `BuildMessages`
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs`: the same place
- Modify: `src/AI.Sentinel.Copilot/CopilotHookConfig.cs`: add the property, parse it, and copy it in `ToSharedConfig`, lines 51-80
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/PlaceholderGuardTests.cs`, `tests/AI.Sentinel.Tests/Copilot/CopilotHookAdapterTests.cs`

**Interfaces:**
- Consumes: `PlaceholderFormat.Pattern()`, and Task 4's `CopilotHookInput.EffectiveToolArgs`.
- Produces:
  - Public `CopilotHookConfig.RedactToolResults { get; init; } = true`, read from `SENTINEL_HOOK_REDACT` with the same parse as `HookConfig`.
  - `internal static class PlaceholderGuard` with:
    - `FrozenSet<string> ClaudeCodeTools`, ordinal: `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash`;
    - `FrozenSet<string> CopilotTools`, ordinal: `create`, `edit`, `str_replace_editor`, `apply_patch`, `bash`, `powershell`;
    - `HookOutput? Check(string? toolName, JsonElement? toolInput, FrozenSet<string> guardedTools)`, which returns a Block or null;
    - `const string Reason = "AI.Sentinel denied this call: its input contains a redaction placeholder such as [EMAIL_1_k3f9x2]. The real value was redacted and must not be written to a file or a command. Ask the user for the value if you need it."`

- [ ] **Step 1: Write the failing tests.**
  - In `PlaceholderGuardTests`:
    - `Write_WithPlaceholderInContent_Denied`;
    - `Bash_WithPlaceholderInCommand_Denied`;
    - `NestedPlaceholderInMultiEditEdits_Denied`;
    - `Read_WithPlaceholder_Allowed`;
    - `Write_WithoutPlaceholder_Allowed`;
    - `UntaggedLookalike_EMAIL_1_Allowed`;
    - `ToolNameCaseMismatch_write_NotGuardedForClaudeCode`;
    - `Reason_IsFixedCopy_NoInputEcho`: the reason never contains the input text.
  - In `HookAdapterTests`:
    - `PreToolUse_WritePlaceholder_BlockWithGuardReason`;
    - `PreToolUse_WritePlaceholder_RedactOff_NotGuarded`.
  - In `CopilotHookAdapterTests`:
    - `CopilotGuard_EditWithPlaceholder_Denies`;
    - `CopilotGuard_ToolArgsAsJsonString_Denies`;
    - `CopilotGuard_View_Allowed`.
- [ ] **Step 2: Run** `--filter-class "*PlaceholderGuardTests*"`, `"*HookAdapterTests*"` and `"*CopilotHookAdapterTests*"`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Check` walks every string leaf. A string-kind root counts too. It matches with `PlaceholderFormat.Pattern().IsMatch`. Both adapters call it only when `RedactToolResults` is set, and return its output before the scan.
- [ ] **Step 4: Run** the step 2 classes. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.ClaudeCode src/AI.Sentinel.Copilot tests/AI.Sentinel.Tests/ClaudeCode tests/AI.Sentinel.Tests/Copilot
git commit -m "feat(hooks): deny writes and shell commands that carry a redaction placeholder

A model that read a redacted tool result might write the placeholder into a
file or a command. PreToolUse now denies Write, Edit, MultiEdit,
NotebookEdit and Bash in Claude Code, and create, edit, str_replace_editor,
apply_patch, bash and powershell in Copilot, when their input holds one.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Copilot postToolUse redaction and userPromptTransformed

**Files:**
- Modify: `src/AI.Sentinel.Copilot/CopilotHookEvent.cs`: append `UserPromptTransformed`
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs`
- Modify: `src/AI.Sentinel.Copilot/AssemblyAttributes.cs`: add `InternalsVisibleTo("AI.Sentinel.Copilot.Cli")`
- Modify: `src/AI.Sentinel.ClaudeCode/HookPipelineRunner.cs`: add the prompt variant
- Create: `src/AI.Sentinel.Copilot.Cli/CopilotWireOutput.cs`, holding the records and `CopilotWireJsonContext`
- Modify: `src/AI.Sentinel.Copilot.Cli/Program.cs`:
  - usage, line 48;
  - stdout, lines 79-103;
  - `ExitCodeAsync`, lines 145-151;
  - `TryParseEvent`, lines 310-320;
  - the semantic-warning condition at line 94.
- Test: `tests/AI.Sentinel.Tests/Copilot/CopilotHookAdapterTests.cs`, `CopilotHookCliTests.cs`, `CopilotHookCliAuditTests.cs`, and `tests/AI.Sentinel.Tests/ClaudeCode/HookWireFormatTests.cs`

**Interfaces:**
- Consumes: Task 5's `HookPipelineRunner.RunToolResultAsync`, `WithheldPrefix` and `JsonString`; Task 4's `EffectiveToolArgs` and `ToolResult`; Task 6's `CopilotHookConfig.RedactToolResults`.
- Produces:
  - `CopilotHookEvent.UserPromptTransformed`, appended last.
  - `internal static Task<(HookOutput Output, string? Rewritten)> HookPipelineRunner.RunPromptAsync(IServiceProvider provider, HookConfig config, string prompt, string? sessionId, CancellationToken ct)`. A Block gives `WithheldPrefix + Reason`. A redaction gives the redacted prompt. Otherwise it is null.
  - `internal sealed record CopilotHookResult(HookOutput Output, string? ModifiedTransformedPrompt)`.
  - `internal Task<CopilotHookResult> CopilotHookAdapter.HandleForCliAsync(CopilotHookEvent evt, CopilotHookInput input, CancellationToken ct)`. The public `HandleAsync` returns `(await HandleForCliAsync(...)).Output`.
  - In `AI.Sentinel.Copilot.Cli`, all internal:
    - `sealed record CopilotWireOutput { HookDecision Decision; string? Reason; CopilotModifiedResult? ModifiedResult; string? ModifiedTransformedPrompt; static CopilotWireOutput From(CopilotHookEvent evt, CopilotHookResult result); }`. The last two members are `WhenWritingNull`, and `reason` keeps its null.
    - `sealed record CopilotModifiedResult(string ResultType, string TextResultForLlm)`.
    - `CopilotWireJsonContext`, camelCase with `UseStringEnumConverter`.

- [ ] **Step 1: Write the failing tests.**
  - Wire tests in `HookWireFormatTests`:
    - `CopilotWire_Allow_LegacyShapeUnchanged`: `{"decision":"Allow","reason":null}`.
    - `CopilotWire_PostToolUseRedacted`: `{"decision":"Allow","reason":null,"modifiedResult":{"resultType":"success","textResultForLlm":"mail [EMAIL_1_abc123]"}}`.
    - `CopilotWire_PostToolUseBlock_Withheld`: `textResultForLlm` is `withheld by AI.Sentinel: r`.
    - `CopilotWire_UserPromptTransformed`: `{"decision":"Allow","reason":null,"modifiedTransformedPrompt":"..."}`.
  - Adapter tests in `CopilotHookAdapterTests`:
    - `PostToolUse_EmailInTextResultForLlm_Redacted`;
    - `PostToolUse_OnlyLegacyToolResponse_NotRedacted_FallsBack`;
    - `UserPromptTransformed_EmailRedacted`;
    - `UserPromptTransformed_Injection_Withheld`;
    - `UserPromptSubmitted_Email_FallsBack`.
  - CLI tests in `CopilotHookCliTests`:
    - `Cli_UserPromptTransformedVerb_Parses`;
    - `Cli_PostToolUse_Injection_ExitZero_WithModifiedResult`;
    - `Cli_PreToolUse_Injection_ExitsTwo`, which is unchanged.
  - Audit tests in `CopilotHookCliAuditTests`: `PostToolUseRedaction_RecordedWithCopilotSource`.
- [ ] **Step 2: Run** `--filter-class "*Copilot*"` and `"*HookWireFormatTests*"`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.**
  - **postToolUse.** Redact `input.ToolResult` as JSON through `RunToolResultAsync`. The context is `tool:{name} input:{EffectiveToolArgs raw}`. `CopilotWireOutput.From` builds `modifiedResult` from:
    - `UpdatedToolOutput.textResultForLlm` when the redacted output is an object;
    - the element's string when it is a string, which is the withheld case.
  - **userPromptTransformed.** Scan `TransformedPrompt ?? Prompt` through `RunPromptAsync` with role User.
  - **Exit codes.** A Block on postToolUse or userPromptTransformed exits 0, with the reason on stderr. Copilot parses stdout only on exit 0, and exit 2 there is just a warning. preToolUse and userPromptSubmitted keep exit 2.
- [ ] **Step 4: Run** the step 2 classes. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel.Copilot src/AI.Sentinel.Copilot.Cli src/AI.Sentinel.ClaudeCode/HookPipelineRunner.cs tests/AI.Sentinel.Tests/Copilot tests/AI.Sentinel.Tests/ClaudeCode/HookWireFormatTests.cs
git commit -m "feat(copilot): redact tool results and the transformed prompt

postToolUse answers with modifiedResult holding the redacted text, and a block
withholds the result. The new user-prompt-transformed verb rewrites what the
model receives through modifiedTransformedPrompt. It stays experimental until
a live check with the Copilot CLI confirms command hooks honour it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Chat-client hosted tool contents

**Files:**
- Modify: `src/AI.Sentinel/Redaction/RedactionSession.cs`:
  - `MapContent`, lines 564-599;
  - `AnsweredCalls`, lines 525-548;
  - `MapApprovalCall` and `CopyApprovalRequest`, lines 665-690.
- Test: `tests/AI.Sentinel.Tests/Redaction/RedactionHostedContentTests.cs`

**Interfaces:**
- Consumes: the existing `MapContent`, `MapValue`, `MapContents`, `CopyMetadata` and `RestoreToolArgument`.
- Produces: no new signatures. `MapContent` gains cases for:
  - `McpServerToolCallContent`, through `Arguments`;
  - `McpServerToolResultContent`, through `Outputs`;
  - `CodeInterpreterToolCallContent`, through `Inputs`;
  - `CodeInterpreterToolResultContent`, through `Outputs`;
  - `WebSearchToolCallContent`, through `Queries`;
  - `WebSearchToolResultContent`, through `Outputs`;
  - `ImageGenerationToolResultContent`, through `Outputs`.
  
  `ImageGenerationToolCallContent` has no text and passes through. `ToolApprovalRequestContent` and `ToolApprovalResponseContent` accept any `ToolCallContent`. `AnsweredCalls` keys on `ToolCallContent` and `ToolResultContent` by `CallId`.

- [ ] **Step 1: Write the failing tests** with `new RedactionSession([new PiiLeakageDetector(), new CredentialExposureDetector()], "abc123")`.
  - `McpServerToolCall_ArgumentsRedacted_UnansweredRestore_PiiYesSecretNo`;
  - `McpServerToolCall_AnsweredByResult_RestoredFully`;
  - `McpServerToolResult_OutputsRedactedAndRestored`;
  - `CodeInterpreterCallAndResult_Redacted`;
  - `WebSearchQueriesAndResult_Redacted`;
  - `ImageGenerationResult_TextOutputRedacted_CallPassesThrough`;
  - `ApprovalRequest_WithMcpServerToolCall_RedactedThenRestoredByToolRule`;
  - `ApprovalResponse_WithMcpServerToolCall_RedactedThenRestoredByToolRule`;
  - `HostedCopies_KeepCallIdNameServerNameAndMetadata`.
- [ ] **Step 2: Run** `--filter-class "*RedactionHostedContentTests*"`. Expected: FAIL, because the values pass through unredacted.
- [ ] **Step 3: Implement.**
  - **Copies.** Each case copies through the type's constructor: `CallId`, plus `Name` and `ServerName` for MCP. Then set the mapped collection and `CopyMetadata`.
  - **Restore.** A hosted call follows the tool rule unless answered, exactly as `FunctionCallContent` does. Results restore fully.
  - **Approval copy.** Generalize `CopyApprovalRequest` to `ToolCallContent`. After the JSON copy, set the copied call's mutable members (`Arguments`, `Inputs` or `Queries`) from the mapped call.
- [ ] **Step 4: Run** `--filter-class "*Redaction*"`. Expected: PASS.
- [ ] **Step 5: Commit.**

```bash
git add src/AI.Sentinel/Redaction/RedactionSession.cs tests/AI.Sentinel.Tests/Redaction/RedactionHostedContentTests.cs
git commit -m "feat(redaction): redact hosted tool call and result contents

MCP server, code interpreter, web search and image generation contents, and
approvals that carry them, are now redacted on the way to the model and
restored by the tool rule.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Docs, README, EU AI Act page, report note and live checks

**Files:**
- Modify: `website/docs/redaction.md`:
  - lines 24-46, the "What changed regardless" hook and proxy sentences;
  - line 87, the "Not redacted" paragraph;
  - the approval bullet in "What is redacted";
  - lines 150-156, "Fallback";
  - add a "Per surface" section after "What is redacted".
- Modify: `website/docs/integrations/claude-code.md`, lines 67-73
- Modify: `website/docs/integrations/copilot.md`, around line 74, plus its verb list and env table
- Modify: `website/docs/integrations/mcp-proxy.md`, around line 79, plus its env table
- Modify: `website/docs/eu-ai-act.md`, lines 20 and 48
- Modify: `website/docs/compliance-report.md`, line 69
- Modify: `README.md`, line 300 for the Art. 10 row, and the Redaction section around line 572
- Modify: `src/AI.Sentinel.Cli/Report/ComplianceReport.cs`, `Art10NoRedactionsNote`, lines 56-57
- Test: the existing `tests/AI.Sentinel.Tests/Cli/ReportCommandTests.cs` and `ComplianceReportBuilderTests.cs`, which reference the constant

**Interfaces:**
- Consumes: the behaviour and env vars of Tasks 2-8.
- Produces: `ComplianceReport.Art10NoRedactionsNote` equals `"No redaction was recorded in this period. The in-process client, the hook CLIs and the MCP proxy record redactions where the host lets them rewrite content; a detection that wanted redaction where it could not is counted as could not be redacted."`

- [ ] **Step 1: Update the report note** and run `--filter-class "*ComplianceReport*"` and `"*ReportCommandTests*"`. Expected: PASS.
- [ ] **Step 2: Add the per-surface table to `redaction.md`.** Columns are Surface, What is redacted, Restored, and Falls back. Rows:
  - In-process client;
  - MCP proxy: tool results, prompts and text resources; PII into later tool calls with a 30-minute idle expiry;
  - Claude Code PostToolUse: `updatedToolOutput`;
  - Claude Code PreToolUse: placeholder guard, otherwise fallback;
  - Claude Code UserPromptSubmit: fallback;
  - Copilot postToolUse: `modifiedResult`;
  - Copilot userPromptTransformed: experimental;
  - Copilot preToolUse: guard;
  - Copilot userPromptSubmitted: fallback.
  
  Also:
  - Move hosted tool content out of "Not redacted".
  - Make the approval bullet "the function call inside a tool approval request or response".
  - Replace the Fallback bullet "in the hook CLIs and the MCP proxy in 3.0" with the remaining limits: tool arguments, UserPromptSubmit and userPromptSubmitted, and blob, non-allowlisted or oversize MCP content.
- [ ] **Step 3: Update the integration pages.**
  - **Claude Code.** Change the action list to: Block exits 2 on PreToolUse and UserPromptSubmit; Block withholds the output on PostToolUse; Warn is a `systemMessage`; Allow is `{}`. Document `SENTINEL_HOOK_REDACT` and the placeholder guard. Note that a built-in tool may reject `updatedToolOutput`, and that `additionalContext` is the mitigation then.
  - **Copilot.** Add the `user-prompt-transformed` verb, marked experimental, and the `toolArgs` fix.
  - **MCP proxy.** Add `SENTINEL_MCP_REDACT`, `SENTINEL_MCP_REDACT_TTL_MIN`, PII restore, and "secrets never".
- [ ] **Step 4: Update the EU AI Act page, README and compliance-report page.**
  - Drop "in-process only" and the #364 link from the EU AI Act line 20, the line-48 bullet, the README Art. 10 row and `compliance-report.md` line 69.
  - State the remaining limits: no argument redaction, no prompt redaction on Claude Code UserPromptSubmit or Copilot userPromptSubmitted, and an experimental userPromptTransformed.
- [ ] **Step 5: Run** `cd website && npm run build`. Expected: no broken-link errors. Then run `dotnet format whitespace . --folder --verify-no-changes` and the full `dotnet test`. Expected: PASS.
- [ ] **Step 6: Run the live checks** and record the commands and results in the PR body.
  1. **Claude Code allow output.** Configure `.claude/settings.json` hooks with `sentinel-hook pre-tool-use` and `sentinel-hook post-tool-use`, run `claude -p "list the files here" --debug`, and expect no hook JSON validation error in the debug output.
  2. **Claude Code redaction.** Write `pii.txt` containing `jan@example.com`, then run `claude -p "Read pii.txt and quote it exactly"`. Expect the reply to quote `[EMAIL_1_` and not the address. If `Read` rejects the shape, record it, note that `additionalContext` applied, and keep the docs caveat.
  3. **Copilot transformed prompt.** If a Copilot CLI is available, configure `userPromptTransformed` with `sentinel-copilot-hook user-prompt-transformed`, run `copilot -p "my mail is jan@example.com, repeat it"`, and record whether the model sees the placeholder. Only a confirmed result removes "experimental" from the Copilot page.
- [ ] **Step 7: Commit, push and open the PR.**

```bash
git add website README.md src/AI.Sentinel.Cli/Report/ComplianceReport.cs
git commit -m "docs(redaction): document redaction in the hook CLIs and the MCP proxy

Per-surface table, new env vars, the Claude Code wire output and the
placeholder guard. The EU AI Act page, the README Art. 10 row and the
report note no longer say redaction is in-process only.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/hook-mcp-redaction
```

Open the PR closing #364, with the live-check results, ending with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. After merge, confirm that each `feat`/`fix` appears in the release-please 3.1.0 PR.

---

## Self-Review

1. **Spec coverage.** Each spec item maps to a task:

   | Spec item | Task |
   |---|---|
   | Shared path, JSON leaf-by-leaf, fallback on error or oversize | 1 |
   | MCP results, prompts and resources, with blob, MIME and oversize fallback | 2 |
   | Response scan judges the redacted result, with arguments redacted in the scan copy only | 1, 2 |
   | Restore with idle expiry and size cap, PII only, store separate from the session, session exports minted | 1, 3 |
   | Copilot field-name bug | 4 |
   | Claude wire bug: `{}`, `systemMessage`, Block exit 2, re-pinned tests | 5 |
   | PostToolUse `updatedToolOutput`, `additionalContext`, withheld on Block | 5 |
   | Placeholder guard on both hosts | 6 |
   | Copilot postToolUse, withheld, `userPromptTransformed` verb and enum, experimental | 7 |
   | Hosted contents and the approval bullet | 8, 9 |
   | Config: `RedactToolResults` and the three env vars | 2, 3, 6 |
   | Public additions | 4, 5, 6, 7 |
   | Audit `Source` and report note | 5, 7, 9 |
   | Docs | 9 |
   | Live checks | 9 |

   The UserPromptSubmit and userPromptSubmitted fallbacks are pinned in Tasks 5 and 7.
2. **Step scan.** Every test step names its tests and their assertions, and every code step names signatures and the spec's values. Bodies are given only for exact copy: the withheld prefix, the guard reason, `additionalContext`, `systemMessage` and the report note.
3. **Type consistency.** These names are used the same way across tasks:
   - `HostContent.FromText`/`FromJson`, `HostRedactionRequest`, `HostRedactionResult.Redacted` and `RedactedByType`;
   - `PlaceholderStore.KnownTokens()`, `Register`, `RestoreToolArguments`, `DefaultIdleExpiry` and `DefaultMaxEntries`;
   - `HookPipelineRunner.RunToolResultAsync`, `RunPromptAsync`, `WithheldPrefix` and `JsonString`;
   - `HookConfig.RedactToolResults` and `CopilotHookConfig.RedactToolResults`;
   - `CopilotHookInput.EffectiveToolArgs`;
   - `CopilotHookResult` and `HandleForCliAsync`.
4. **Review Focus.** Each of the five lines has its test in Tasks 1, 3, 4, 5 and 6.
5. **Proportion.** The plan has no implementation bodies, only signatures, test names, assertions and pinned copy.
