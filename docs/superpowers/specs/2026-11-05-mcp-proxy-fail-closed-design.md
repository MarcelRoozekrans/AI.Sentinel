# MCP proxy fails closed on pipeline errors (#544)

## Intent

When the detection pipeline throws, the MCP proxy logs `decision=FailOpen` and forwards the content unscanned. #478 made the hook CLIs block on internal errors, and #439 turned a regex timeout and oversize content into Critical findings. That leaves the proxy as the one surface where an unexpected pipeline exception lets content through. A broken scanner must not mean an unchecked tool call, prompt or resource.

## Decisions (Marcel, 2026-11-05)

- **Scope: all four fail-open paths fail closed.** These are the `tools/call` request scan, the `tools/call` response scan, the `prompts/get` response scan and the `resources/read` scan. Each path covers both the redacting and the non-redacting mode. A response-side block withholds a result whose tool has already run, as a `ThreatDetected` response block does today. With redaction on, `resources/read` blocks the whole read, not just the item that threw.
- **There is no fail-open switch**, as in #478.
- **Audit: tool calls only.** A fail-closed `tools/call` writes a best-effort `AUTHZ-DENY` entry with `SentinelDenyCodes.InternalError` and forwards it, when the proxy has an audit store. `prompts/get` and `resources/read` log to stderr only, so the audit store is not wired into their interceptors.
- **Error text: exception type only.** The text is `Blocked by AI.Sentinel: internal error (<ExceptionType>)`, raised as `McpProtocolException` with `McpErrorCode.InternalError`, the code a `ThreatDetected` block uses. The message is never passed on or logged, because it can carry the scanned value, which matters most with redaction on.
- **Release: `fix:`, so 5.1.1.** #478 made the same call in 3.6.1. The docs say plainly that a pipeline error now blocks.

## Approaches

- **A. A shared helper at each catch (chosen).** Each fail-open catch calls one `McpFailClosed` helper in `AI.Sentinel.Mcp`, which logs and throws. It is the smallest diff, it reads like the existing `BlockIfThreat` code and it adds no public API.
- **B. The pipeline returns an internal-error `SentinelError` that hosts block on.** Rejected: it adds core public API and changes every host, including the in-process client. That is too wide for a `fix:` and overlaps #550/#564.
- **C. One outer try/catch per interceptor.** Rejected: it would also catch errors from the target server (`next`) and from authorization, and report them as Sentinel internal errors.

## What changes

The catches that fail open on origin/main b6ccfce:

| File | Where | Today |
|---|---|---|
| `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` | `RedactResponseAsync` catch (~164) | `decision=FailOpen phase=response`, returns the result |
| `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` | `ScanSafelyAsync` catch (~347), request and response phases | `decision=FailOpen phase=…`, returns null |
| `src/AI.Sentinel.Mcp/PromptGetInterceptor.cs` | redacting catch (~83) | `decision=FailOpen phase=response`, returns the result |
| `src/AI.Sentinel.Mcp/PromptGetInterceptor.cs` | `ScanSafelyAsync` catch (~194) | `decision=FailOpen`, returns null |
| `src/AI.Sentinel.Mcp/ResourceReadInterceptor.cs` | `RedactAsync` per-item catch (~145) | `action=fail_open`, skips the item |
| `src/AI.Sentinel.Mcp/ResourceReadInterceptor.cs` | `ScanSafelyAsync` catch (~205) | `action=fail_open`, returns null |

Each one now logs a fail-closed event and throws the block:

- **`tools/call` and `prompts/get` log** `[sentinel-mcp] event=… decision=FailClosed tool|prompt=<name> phase=<phase> reason=<ExceptionType>`.
- **`resources/read` logs** through `StderrLogger` with `action=fail_closed`, `uri` and `error=<ExceptionType>`, matching its key-value style.
- **The caller's own cancellation propagates** and is not turned into a block: an `OperationCanceledException` passes through only when the request's token is cancelled. Any other one, such as a `TaskCanceledException` from an internal timeout, fails closed. Every fail-closed catch uses `when (ex is not OperationCanceledException || !ct.IsCancellationRequested)`.
- **The tool-call audit entry reuses `HookInternalError.BuildAuditEntry`.** AI.Sentinel.ClaudeCode already exposes its internals to AI.Sentinel.Mcp. The entry's caller comes from `callerResolver` when one is set, and otherwise it is anonymous. Its reason is the agent-facing text, so the type only. A failure to write the entry is logged as `decision=AuditFailed` and never changes the block.
- **Unchanged:**
  - the `AuditFailed` catches around `AppendRedactionsAsync`, because they run after a scan passed and let nothing through unscanned;
  - the redaction-failure fallback inside `McpRedaction.RedactAndScanAsync`, where content is still scanned, unredacted;
  - a single throwing detector, which `DetectionPipeline` still reads as clean. That last one is #550/#564 territory and outside this fix.
- **The XML remarks** on all three interceptors that describe fail-open semantics are rewritten.

## Docs

- `website/docs/integrations/mcp-proxy.md:100`: the "or the pipeline throws" part of the fallbacks bullet changes to say the proxy blocks. Add a short "Pipeline errors" note covering the error text, the stderr event and the tool-call audit entry.
- `website/docs/redaction.md` "Fail closed": that section is about redaction failure and stays true. Check that it does not imply that a scan failure forwards.

## Tests

For each of the four paths, in both modes, use a pipeline whose scan throws:

- **The block:** `McpProtocolException` with `InternalError`, and the message names the exception type but not the exception message.
- **The stderr event:** the fail-closed event is logged, and nothing logs `FailOpen` or `fail_open`.
- **The target is never called** when the request scan throws.
- **Tool calls only, the audit entry:** an `AUTHZ-DENY` / `internal_error` entry is written when an audit store is set, and an audit store that throws still blocks.
- **Cancellation:** a scan cancelled by the caller propagates `OperationCanceledException`; a foreign cancellation fails closed.
- **Existing tests:** any that assert fail-open, such as `*FailsOpen*`, are inverted rather than deleted.

## Left to the builder

- The helper's exact shape and file, and whether the log helpers stay per interceptor.
- How to make the scan throw in tests, through a throwing detector registration or the existing test seams.
