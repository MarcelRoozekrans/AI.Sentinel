# MCP Proxy Fails Closed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the detection pipeline throws, every MCP proxy scan path blocks with an `McpProtocolException` instead of forwarding the content unscanned (#544).

**Architecture:** Each fail-open catch in the three interceptors throws a block built by one shared helper, `McpFailClosed`. Logging stays in each interceptor, in its own format. `tools/call` also writes a best-effort `AUTHZ-DENY` / `internal_error` audit entry, built with #478's `HookInternalError.BuildAuditEntry`.

**Tech Stack:** C# / .NET 8 + 10, ModelContextProtocol 2.3.1, xUnit v3.

**Spec:** `docs/superpowers/specs/2026-11-05-mcp-proxy-fail-closed-design.md`

## Global Constraints

- **Agent-facing error text, exactly:** `Blocked by AI.Sentinel: internal error (<ExceptionType>)`, where `<ExceptionType>` is `ex.GetType().Name`. Raise it as `McpProtocolException` with `McpErrorCode.InternalError`.
- **No exception message**, anywhere: not in the error, not in stderr, not in the audit entry. It can carry the scanned value.
- **No fail-open switch** and no new environment variable.
- **Cancellation:** `OperationCanceledException` propagates unchanged and is never turned into a block.
- **Unchanged:** the `AuditFailed` catches around `AppendRedactionsAsync`, and the redaction-failure fallback inside `McpRedaction.RedactAndScanAsync`.
- **Commits:** typed `fix(mcp): …` or `docs: …`. Bodies have no nested parentheses and no Claude signature or session link.
- **Tests:** run them only with a filter, never as an unfiltered `dotnet test`. Run `dotnet format whitespace --verify-no-changes` before any push.

## Review Focus

1. **A target that would have been called:** a request-scan failure must block before `next` runs, so the target sees no call. Task 2 test `RequestScanThrows_TargetIsNotCalled`.
2. **One bad item among several in a redacting resource read:** the whole read blocks and no item is written back or audited as redacted. Task 4 test `Redacting_OneItemThrows_BlocksWholeRead_NothingWrittenBack`.
3. **An audit store that throws during a fail-closed tool call:** the call still blocks with the same error, and stderr logs `AuditFailed`. Task 2 test `AuditStoreThrows_StillBlocks`.
4. **An exception message that carries a value:** the value never reaches the error or stderr. Every test's exception message is `LeakMarker`, and each test asserts that it is absent.
5. **A cancelled scan:** it surfaces as cancellation, not as a Sentinel block. Covered by the `Cancelled_Propagates` tests in Tasks 2-4.

---

### Task 1: `McpFailClosed` helper and the throwing-pipeline test fixture

**Files:**
- Create: `src/AI.Sentinel.Mcp/McpFailClosed.cs`
- Create: `tests/AI.Sentinel.Tests/Mcp/McpFailClosedFixture.cs`
- Test: `tests/AI.Sentinel.Tests/Mcp/McpFailClosedTests.cs`

**Interfaces:**
- Produces (src):
  - `internal static class McpFailClosed` with
  - `internal const string Prefix = "Blocked by AI.Sentinel: internal error";`
  - `internal static McpProtocolException Block(Exception ex)`, which returns the message `$"{Prefix} ({ex.GetType().Name})"` with `McpErrorCode.InternalError`.
- Produces (tests), `internal static class McpFailClosedFixture`:
  - `const string LeakMarker = "leak-4111111111111111";`
  - `static SentinelPipeline ThrowingPipeline(Func<Exception>? exception = null)`. It builds `new SentinelPipeline(new NullClient(), new ThrowingDetectionPipeline(exception), new RingBufferAuditStore(100), new InterventionEngine(opts, null), opts)`, the same construction as `ToolCallNewMessagesTests.Build`. The default exception is `new InvalidOperationException(LeakMarker)`.
  - `ThrowingDetectionPipeline : IDetectionPipeline`, whose `RunAsync` throws `exception()`.
  - `static RequestContext<T> Context<T>(T parameters)`, the same as the existing `GetUninitializedObject` helpers.
  - `static PlaceholderStore NewStore() => new(PlaceholderStore.DefaultIdleExpiry);`
  - `static void AssertFailClosed(McpProtocolException ex)`. It asserts that `ex.ErrorCode == McpErrorCode.InternalError`, that `ex.Message` contains `"Blocked by AI.Sentinel: internal error (InvalidOperationException)"`, and that it does not contain `LeakMarker`.

- [ ] **Step 1: Write the failing test** `McpFailClosedTests.Block_NamesTheTypeOnly`. It calls `McpFailClosed.Block(new InvalidOperationException(LeakMarker))` and passes the result to `AssertFailClosed`.
- [ ] **Step 2: Run it and check that it fails to compile.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~McpFailClosedTests"`. Expected: a build error, because `McpFailClosed` does not exist.
- [ ] **Step 3: Implement `McpFailClosed` and the fixture.** Give the helper a summary that cites #544 and #478.
- [ ] **Step 4: Run the same command again.** Expected: PASS.
- [ ] **Step 5: Commit.** Message: `fix(mcp): add the fail-closed block for pipeline errors`.

### Task 2: `tools/call` fails closed in both phases and both modes, with an audit entry

**Files:**
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs`:
  - the class remarks (lines 23-38);
  - the `RedactResponseAsync` catch and its summary (~146-170);
  - `ScanSafelyAsync` (~335-354).
- Test: `tests/AI.Sentinel.Tests/Mcp/McpFailClosedTests.cs`
- Test: `tests/AI.Sentinel.Tests/Mcp/ConcurrencyAndAdversarialTests.cs:93`. Rename `TargetReturnsUnparseableBlob_ProxyFailsOpen` to `TargetReturnsEmptyContent_ProxyForwards` and fix its comment. Empty content returns before any scan, so the test still forwards.

**Interfaces:**
- Consumes: `McpFailClosed.Block`, `HookInternalError.BuildAuditEntry(ISecurityContext caller, string? toolName, string sessionId, string reason)`, and `AuditForwarding`'s `store.AppendAndForwardAsync(entry, forwarders, ct)`. The hook CLIs use the last one.
- Produces: `private static async ValueTask<McpProtocolException> FailClosedAsync(Exception ex, string phase, CallToolRequestParams req, TextWriter stderr, IAuditStore? audit, IAuditForwarder[] forwarders, Func<CallToolRequestParams, ISecurityContext>? callerResolver, SessionId? sessionId)` in `ToolCallInterceptor`. It does three things, in this order:
  1. It logs `[sentinel-mcp] event=tools/call decision=FailClosed tool=<name> phase=<phase> reason=<Type>`.
  2. When `audit` is not null, it appends and forwards `BuildAuditEntry(callerResolver?.Invoke(req) ?? AnonymousSecurityContext.Instance, req.Name, sessionId?.Value ?? "", <block message>)` with `CancellationToken.None`. On an exception there, it logs `[sentinel-mcp] event=tools/call decision=AuditFailed phase=fail_closed reason=<Type>`.
  3. It returns `McpFailClosed.Block(ex)`.

  The catches are `when (ex is not OperationCanceledException)` and end in `throw await FailClosedAsync(...)`. Thread `audit`, `forwarders` and `callerResolver` into `ScanSafelyAsync` and `RedactResponseAsync`. `ScanSafelyAsync` no longer returns null on an error.

- [ ] **Step 1: Write the failing tests** in `McpFailClosedTests`. Each test uses `ThrowingPipeline()`, captures stderr with a `StringWriter`, uses a `next` that counts its calls and returns `new CallToolResult { Content = [new TextContentBlock { Text = "ok" }] }`, and uses tool `read_file`.
  - `ToolCall_RequestScanThrows_TargetIsNotCalled`: `AssertFailClosed`. `next` is called 0 times. stderr contains `decision=FailClosed tool=read_file phase=request reason=InvalidOperationException` and does not contain `FailOpen` or `LeakMarker`.
  - `ToolCall_ResponseScanThrows_BlocksResult`, with `[Theory]` `redacting: false/true`, where `true` passes `placeholders: NewStore()`. The pipeline throws only on the 2nd `RunAsync` call: use a counter in the `exception` factory, and have the 1st call return a clean `PipelineResult` instead of throwing. Extend `ThrowingDetectionPipeline` with a `throwFromCall` int, defaulting to 1. Asserts: `AssertFailClosed`, `next` called once, and stderr contains `phase=response`.
  - `ToolCall_FailClosed_WritesInternalErrorAuditEntry`: `audit: store` is a `RingBufferAuditStore`, and `forwarders: [new RecordingAuditForwarder()]`. Exactly one entry has `DetectorId == "AUTHZ-DENY"`, its policy code is `SentinelDenyCodes.InternalError`, its reason contains `InvalidOperationException` and not `LeakMarker`, and the forwarder received it.
  - `ToolCall_AuditStoreThrows_StillBlocks`: use an `IAuditStore` whose append throws. Asserts: `AssertFailClosed`, and stderr contains `decision=AuditFailed phase=fail_closed`.
  - `ToolCall_Cancelled_Propagates`: the exception factory returns `new OperationCanceledException()`. Asserts `Assert.ThrowsAnyAsync<OperationCanceledException>` and that stderr has no `FailClosed`.
- [ ] **Step 2: Run the tests and check that they fail.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~McpFailClosedTests"`. Expected: the new tests fail, because the call forwards and logs `FailOpen`.
- [ ] **Step 3: Implement `FailClosedAsync` and rewire both catches.** Rewrite the class remarks and the `RedactResponseAsync` summary so they state the fail-closed behaviour.
- [ ] **Step 4: Run the tests and check that they pass.** Run `dotnet test tests/AI.Sentinel.Tests -f net10.0 --filter "FullyQualifiedName~AI.Sentinel.Tests.Mcp"`. Expected: all pass. Repeat with `-f net8.0`.
- [ ] **Step 5: Commit.** Message: `fix(mcp): tools/call fails closed when the pipeline throws`.

### Task 3: `prompts/get` fails closed in both modes

**Files:**
- Modify: `src/AI.Sentinel.Mcp/PromptGetInterceptor.cs`:
  - the remarks (lines 17-21);
  - the redacting catch (~83);
  - `ScanSafelyAsync` (~183-201).
- Test: `tests/AI.Sentinel.Tests/Mcp/McpFailClosedTests.cs`

**Interfaces:**
- Consumes: `McpFailClosed.Block`.
- Produces: the log line `[sentinel-mcp] event=prompts/get decision=FailClosed prompt=<name> phase=response reason=<Type>`. There is no audit entry. Both catches are `when (ex is not OperationCanceledException)` and throw `McpFailClosed.Block(ex)` after logging.

- [ ] **Step 1: Write the failing tests.** `next` returns a single user `PromptMessage` with the text `"hello"`.
  - `PromptGet_ScanThrows_Blocks`, with `[Theory]` `redacting: false/true`. Asserts: `AssertFailClosed`, and stderr contains `event=prompts/get decision=FailClosed prompt=onboard phase=response reason=InvalidOperationException` and does not contain `FailOpen` or `LeakMarker`.
  - `PromptGet_Cancelled_Propagates`.
- [ ] **Step 2: Run the tests and check that they fail.** Use the same filter as Task 2. Expected: the new tests fail.
- [ ] **Step 3: Implement the change.** Rewrite the remarks so they no longer say "fail-open to stderr".
- [ ] **Step 4: Run the Task 2 Step 4 commands on both TFMs.** Expected: all pass.
- [ ] **Step 5: Commit.** Message: `fix(mcp): prompts/get fails closed when the pipeline throws`.

### Task 4: `resources/read` fails closed in both modes, and the docs

**Files:**
- Modify: `src/AI.Sentinel.Mcp/ResourceReadInterceptor.cs`:
  - the remarks (lines 26-31), "Detection-pipeline failures fail open";
  - the `RedactAsync` summary and its per-item catch (~120-150);
  - `ScanSafelyAsync` (~197-210);
  - `LogFailOpen`, which is replaced by `LogFailClosed`.
- Modify: `website/docs/integrations/mcp-proxy.md:100`.
- Check: `website/docs/redaction.md` "Fail closed" (line 235). Change it only if it implies that a scan failure forwards.
- Test: `tests/AI.Sentinel.Tests/Mcp/McpFailClosedTests.cs`

**Interfaces:**
- Consumes: `McpFailClosed.Block`.
- Produces: `private static McpProtocolException LogFailClosed(string uri, string error)`. It logs through `StderrLogger` with `event=resources_read`, `action=fail_closed`, `uri` and `error`, and returns `McpFailClosed.Block`. A per-item exception in `RedactAsync` throws before the write-back loop, so no item is written back or audited.

- [ ] **Step 1: Write the failing tests.** Capture stderr with `Console.SetError`, as `ResourceReadInterceptorTests.CaptureStderrAsync` does, because this interceptor logs through `StderrLogger`. Mark the test class `[Collection("NonParallel")]` for these tests, or put the resource tests in a separate class with that collection.
  - `ResourceRead_ScanThrows_Blocks`, with `[Theory]` `redacting: false/true`. The resource is `file:///x.txt`, `text/plain`, `"hello"`. Asserts: `AssertFailClosed`, stderr contains `fail_closed` and `InvalidOperationException`, and it does not contain `fail_open` or `LeakMarker`.
  - `Redacting_OneItemThrows_BlocksWholeRead_NothingWrittenBack`. There are two items: item 1 has `"mail a@example.com"`, which the scan cleans, and item 2 throws (`throwFromCall: 2`). Asserts: `AssertFailClosed`, both items' `Text` is unchanged on the original result object, and the pipeline's audit store holds no `REDACTED` entry.
  - `ResourceRead_Cancelled_Propagates`.
- [ ] **Step 2: Run the tests and check that they fail.** Use the Task 2 filter. Expected: the new tests fail.
- [ ] **Step 3: Implement the change.** Rewrite the remarks and the `RedactAsync` summary.
- [ ] **Step 4: Update the docs.**
  - In `mcp-proxy.md:100`, the fallbacks bullet keeps the rate-limit sentence. Its pipeline part becomes: when the pipeline throws, the proxy blocks.
  - Add a `### Pipeline errors` subsection near the audit section. It says:
    - The proxy blocks the call, prompt or read with `Blocked by AI.Sentinel: internal error (<ExceptionType>)`.
    - It logs `decision=FailClosed` on stderr, or `action=fail_closed` for `resources/read`.
    - For a tool call, it writes an `AUTHZ-DENY` entry with the `internal_error` code.
    - A tool whose result scan fails has already run.
    - There is no switch to fail open, as with the hook CLIs.
    - A single failing detector is still skipped and reported, not blocked.
- [ ] **Step 5: Run the Mcp tests on both TFMs** with the Task 2 Step 4 commands. Then run `dotnet format whitespace --verify-no-changes`. Expected: all pass, and format reports no changes.
- [ ] **Step 6: Commit.** Message: `fix(mcp): resources/read fails closed when the pipeline throws`. The docs go in the same commit.
