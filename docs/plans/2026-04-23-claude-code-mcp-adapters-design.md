# Claude Code Hook + Copilot Hook + MCP Proxy Adapters Design

**Goal:** Integrate AI.Sentinel into the three tool-call interception surfaces that matter for modern AI coding: Claude Code native hooks, GitHub Copilot native hooks, and the cross-vendor MCP protocol (Cursor, Continue, Cline, Windsurf, plus Copilot's own MCP support). Run the detector pipeline on tool inputs, tool outputs, and user prompts; block or warn on threats.

**Architecture:** Six new packages. Three integration paths × (library + dotnet tool CLI). Claude Code and Copilot hooks are structurally identical (command-line hooks with stdin JSON payloads, different field names); the Copilot library depends on Claude Code's for shared types (`HookDecision`, `HookConfig`, `HookSeverityMapper`, `HookPipelineRunner`). The MCP CLI is a long-lived stdio proxy.

**Tech Stack:** `Microsoft.Extensions.AI` (`IChatClient`, `ChatMessage`, reused via `AI.Sentinel`), `ModelContextProtocol 1.2.*` NuGet (MCP SDK), `System.Text.Json` source generators for AOT-ready JSON in hook CLIs, stdio JSON-RPC 2.0 for MCP.

---

## Package structure

```
src/
├── AI.Sentinel.ClaudeCode/           (library, net8.0;net9.0 — also hosts shared hook core)
├── AI.Sentinel.ClaudeCode.Cli/       (dotnet tool, net8.0, AOT-ready)
├── AI.Sentinel.Copilot/              (library, net8.0;net9.0 — references ClaudeCode for shared core)
├── AI.Sentinel.Copilot.Cli/          (dotnet tool, net8.0, AOT-ready)
├── AI.Sentinel.Mcp/                  (library, net8.0;net9.0)
└── AI.Sentinel.Mcp.Cli/              (dotnet tool, net8.0)
```

**Why split library + CLI per integration:** the Claude Code library exposes `HookAdapter` for programmatic use (tests, custom hook runners). Same for the Copilot adapter and `McpProxy`. CLI packages are thin shells. Single-package embedding (like `AI.Sentinel.Cli`) doesn't work here because `PackAsTool=true` packages aren't consumable via `PackageReference` — the DLL lands in `tools/` not `lib/`.

**Why Copilot references Claude Code:** `HookDecision`, `HookConfig`, `HookSeverityMapper`, and the generic `HookPipelineRunner` (builds `ChatMessage[]` → runs pipeline → maps severity) are vendor-agnostic. Rather than extract a third "core" package (YAGNI until a third hook vendor lands), the Copilot library depends on the ClaudeCode library for these. Copilot-specific types (`CopilotHookEvent`, `CopilotHookInput`, `CopilotHookAdapter`, `CopilotHookJsonContext`) live in the Copilot library.

---

## Claude Code hook adapter

### Data flow

```
Claude Code runs: sentinel-hook pre-tool-use
  │
  ├─ stdin: {"tool_name":"Bash","tool_input":{"command":"..."},"session_id":"..."}
  │
  ├─ HookInput deserialized via source-gen JsonSerializerContext (AOT-safe)
  ├─ HookAdapter translates → ChatMessage[]
  ├─ SentinelPipeline.GetResponseResultAsync runs rule-based detectors
  ├─ Severity → HookDecision mapping
  │
  ├─ stdout: {"decision":"block","reason":"SEC-01 PromptInjection: ..."}
  └─ exit code: 0 (allow/warn) or 2 (block)
```

### Event-to-ChatMessage mapping

| Hook event | Mapping |
|---|---|
| `user-prompt-submit` | `[ChatMessage(User, prompt_text)]` |
| `pre-tool-use` | `[ChatMessage(User, "tool:{tool_name} input:{json-serialized tool_input}")]` |
| `post-tool-use` | `[ChatMessage(User, "tool:{tool_name} input:{json}"), ChatMessage(Assistant, tool_result_text)]` |

`post-tool-use` uses two roles so that detectors filtering by `ChatRole.Assistant` (e.g., `SystemPromptLeakageDetector`) fire on tool output.

### Severity → decision mapping

Configured via environment variables (hooks don't accept CLI flags at run time — Claude Code invokes the command verbatim):

| Variable | Default |
|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` |
| `SENTINEL_HOOK_ON_HIGH` | `Block` |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` |
| `SENTINEL_HOOK_ON_LOW` | `Allow` |
| `SENTINEL_HOOK_VERBOSE` | `0` (set to `1` for stderr reason JSON) |

`Block` → exit 2 with reason on stderr. `Warn` → stderr note, exit 0. `Allow` → silent exit 0.

### No LLM-escalation

`SentinelOptions.EscalationClient = null` always. Hooks fire on every tool call; an LLM classifier per-call would be cost-prohibitive and high-latency.

### Native AOT

`AI.Sentinel.ClaudeCode.Cli.csproj` sets `<PublishAot>true</PublishAot>`. Cold start drops from ~300 ms to ~30 ms — critical for IDE responsiveness. Library (`AI.Sentinel.ClaudeCode`) stays reflection-friendly for programmatic use; only the CLI is AOT-compiled.

AOT constraints require:
- Source-generated JSON via `JsonSerializerContext` (no reflection-based deserialization of `HookInput`/`HookOutput`)
- No runtime code generation in the hot path

---

## Copilot hook adapter

GitHub Copilot's hook system is structurally similar to Claude Code's — command-line hooks triggered at session / prompt / tool-call events, configured via a `hooks.json` file, communicating via stdin JSON + exit codes. The field names differ (camelCase vs snake_case).

### Event mapping

| Copilot event | AI.Sentinel interest | Mapping |
|---|---|---|
| `sessionStart` | None (no content) | Not handled |
| `sessionEnd` | None | Not handled |
| `userPromptSubmitted` | Scan user prompt | `[ChatMessage(User, prompt)]` |
| `preToolUse` | Scan tool args | `[ChatMessage(User, "tool:{toolName} input:{toolInput-json}")]` |
| `postToolUse` | Scan tool result | Two-role scan: User prompt + Assistant tool-result |

### Payload field differences from Claude Code

| Claude Code field | Copilot field |
|---|---|
| `session_id` | `sessionId` |
| `tool_name` | `toolName` |
| `tool_input` | `toolInput` |
| `tool_response` | `toolResponse` |

### Shared core

`AI.Sentinel.Copilot` references `AI.Sentinel.ClaudeCode` and reuses:
- `HookDecision` enum
- `HookConfig` + env-var loader
- `HookSeverityMapper`
- `HookPipelineRunner` (the generic `ChatMessage[]` → pipeline → `HookOutput` core)

Copilot-specific classes:
- `CopilotHookEvent` enum (3 values: UserPromptSubmitted, PreToolUse, PostToolUse)
- `CopilotHookInput` record (camelCase JSON field names)
- `CopilotHookAdapter` — maps payload to messages, delegates to `HookPipelineRunner`
- `CopilotHookJsonContext` — source-gen JsonSerializerContext for AOT

### CLI

`sentinel-copilot-hook <event>` — same pattern as `sentinel-hook`. Reads stdin JSON, writes stdout JSON, exits 0/2.

### Env-var config

Same variables as Claude Code (`SENTINEL_HOOK_ON_CRITICAL` etc.) — shared config, shared mapper. Users who install both adapters get one consistent mental model.

---

## MCP proxy

### User configuration

The user configures their MCP host to point at `sentinel-mcp`:

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "sentinel-mcp",
      "args": ["proxy", "--target", "uvx", "mcp-server-filesystem", "/home/me"]
    }
  }
}
```

`sentinel-mcp proxy` spawns `uvx mcp-server-filesystem /home/me` as a subprocess and proxies JSON-RPC messages to/from it.

### Data flow

```
MCP host ──JSON-RPC──> sentinel-mcp ──forwards──> target MCP server
         <────────────             <───────────
                      │
                      ├─ Intercepts tools/call request:
                      │    Scan arguments (prompt direction)
                      │    If threat ≥ Block: return JSON-RPC error, never forward
                      │
                      └─ Intercepts tools/call response:
                           Scan result content (response direction)
                           If threat ≥ Block: replace with JSON-RPC error
                           Else forward with optional log annotation
```

### What's intercepted vs forwarded verbatim

| Message | Behavior |
|---|---|
| `initialize`, `shutdown` | Forward verbatim |
| `tools/list`, `resources/list`, `prompts/list` | Forward verbatim (metadata isn't content) |
| `tools/call` request | Scan `arguments` JSON |
| `tools/call` response | Scan `content` text |
| `resources/read` response | Forward verbatim v1 — can add later |
| All other notifications | Forward verbatim |

### Block response format

```json
{
  "jsonrpc": "2.0",
  "id": <request-id>,
  "error": {
    "code": -32000,
    "message": "Blocked by AI.Sentinel: SEC-01 PromptInjection"
  }
}
```

The MCP host surfaces this as a tool failure to the LLM, which can then react appropriately (retry with different args, give up, etc.).

### Transport

**stdio only** for v1. SSE/HTTP transports are defined in the MCP spec but less common for local-first integration. `ModelContextProtocol` NuGet supports stdio out of the box.

### No LLM-escalation in proxy

Same reasoning as Claude Code hooks: tool calls are frequent, LLM classification per-call is cost-prohibitive.

---

## Shared concerns

### Pipeline construction

Both adapters use `ForensicsPipelineFactory`-like wiring:

- `SentinelOptions.EscalationClient = null`
- All severity mappings configurable via env vars (hook) or CLI args (MCP), defaults block Critical/High, warn Medium, allow Low
- All rule-based detectors enabled via `services.AddAISentinel()` + `provider.GetServices<IDetector>()`

Consider extracting a shared `AdapterPipelineFactory` in `AI.Sentinel.ClaudeCode` if the wiring is non-trivial, and let `AI.Sentinel.Mcp` depend on `AI.Sentinel.ClaudeCode`... no, that creates a weird dependency. Just duplicate the ~15 lines across both libraries.

### Configuration philosophy

- Env vars for Claude Code hooks (no CLI-arg mechanism for hooks)
- CLI args for MCP proxy (normal process startup)
- No config file in v1 (YAGNI; users can wrap the CLI in their own script if they need per-project config)

---

## Testing

### `AI.Sentinel.ClaudeCode` library

| Test | Verifies |
|---|---|
| `HookAdapter_UserPromptSubmit_Clean_ReturnsAllow` | Benign prompt → `HookDecision.Allow` |
| `HookAdapter_UserPromptSubmit_PromptInjection_ReturnsBlock` | `ignore all previous instructions` → `Block` with SEC-01 reason |
| `HookAdapter_PreToolUse_MapsToolInputToMessage` | Tool args serialized into synthetic User message |
| `HookAdapter_PostToolUse_ScansAssistantRole` | Tool result placed in Assistant-role message; assistant-only detectors fire |
| `HookAdapter_SeverityMapping_CriticalToBlock` | Env var overrides respected |
| `HookAdapter_SeverityMapping_MediumToWarn` | Default mapping produces `Warn` for Medium |
| `HookAdapter_Verbose_EmitsStderrJson` | `SENTINEL_HOOK_VERBOSE=1` produces JSON reason |

### `AI.Sentinel.ClaudeCode.Cli` integration

| Test | Verifies |
|---|---|
| `Cli_PipedStdin_EmitsStdoutJson` | End-to-end: JSON in → JSON out |
| `Cli_BlockDecision_ExitsTwo` | Critical detection → exit 2 |
| `Cli_AllowDecision_ExitsZero` | Clean → exit 0 |
| `Cli_MalformedStdin_ExitsOne` | Invalid JSON → exit 1 |
| `Cli_UnknownEvent_ExitsOne` | `sentinel-hook foo` → clear error |

### `AI.Sentinel.Mcp` library

| Test | Verifies |
|---|---|
| `McpProxy_ForwardsInitializeVerbatim` | Non-intercepted messages pass through |
| `McpProxy_ToolCall_CleanArgs_ForwardsToTarget` | Clean tool call reaches target |
| `McpProxy_ToolCall_MaliciousArgs_BlocksWithError` | Threat in args → JSON-RPC error, target never called |
| `McpProxy_ToolResult_ContainsPII_BlocksWithError` | Target returns PII → proxy replaces with error |
| `McpProxy_ToolResult_Clean_ForwardsToHost` | Clean result passes through |
| `McpProxy_TargetServerCrashes_PropagatesError` | Target subprocess dies → proxy reports cleanly |

### `AI.Sentinel.Mcp.Cli` integration

| Test | Verifies |
|---|---|
| `Cli_Proxy_StdioHandshake_Succeeds` | `sentinel-mcp proxy --target echo-server` survives MCP initialize |
| `Cli_Proxy_MalformedTargetArgs_ExitsOne` | Missing `--target` → clean error |

MCP tests rely on a small `FakeMcpServer` test double that echoes tool calls — keeps tests hermetic without requiring a real MCP server binary.

---

## Files changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel.ClaudeCode/AI.Sentinel.ClaudeCode.csproj` |
| New | `src/AI.Sentinel.ClaudeCode/HookEvent.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookInput.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookOutput.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookDecision.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookAdapter.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookConfig.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookSeverityMapper.cs` |
| New | `src/AI.Sentinel.ClaudeCode/HookJsonContext.cs` (JsonSerializerContext for AOT) |
| New | `src/AI.Sentinel.ClaudeCode/HookPipelineRunner.cs` (shared core, consumed by Copilot adapter) |
| New | `src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj` |
| New | `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` |
| New | `src/AI.Sentinel.Copilot/AI.Sentinel.Copilot.csproj` |
| New | `src/AI.Sentinel.Copilot/CopilotHookEvent.cs` |
| New | `src/AI.Sentinel.Copilot/CopilotHookInput.cs` |
| New | `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs` |
| New | `src/AI.Sentinel.Copilot/CopilotHookJsonContext.cs` |
| New | `src/AI.Sentinel.Copilot.Cli/AI.Sentinel.Copilot.Cli.csproj` |
| New | `src/AI.Sentinel.Copilot.Cli/Program.cs` |
| New | `src/AI.Sentinel.Mcp/AI.Sentinel.Mcp.csproj` |
| New | `src/AI.Sentinel.Mcp/McpProxy.cs` |
| New | `src/AI.Sentinel.Mcp/ProxyInterception.cs` |
| New | `src/AI.Sentinel.Mcp/McpSeverityMapper.cs` |
| New | `src/AI.Sentinel.Mcp.Cli/AI.Sentinel.Mcp.Cli.csproj` |
| New | `src/AI.Sentinel.Mcp.Cli/Program.cs` |
| New | `src/AI.Sentinel.Mcp.Cli/ProxyCommand.cs` |
| Modify | `AI.Sentinel.slnx` — add 4 projects |
| Modify | `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj` — add 4 project references |
| New | `tests/AI.Sentinel.Tests/ClaudeCode/HookAdapterTests.cs` |
| New | `tests/AI.Sentinel.Tests/ClaudeCode/HookCliTests.cs` |
| New | `tests/AI.Sentinel.Tests/Copilot/CopilotHookAdapterTests.cs` |
| New | `tests/AI.Sentinel.Tests/Copilot/CopilotHookCliTests.cs` |
| New | `tests/AI.Sentinel.Tests/Mcp/McpProxyTests.cs` |
| New | `tests/AI.Sentinel.Tests/Mcp/McpCliTests.cs` |
| New | `tests/AI.Sentinel.Tests/Mcp/FakeMcpServer.cs` |
| Modify | `README.md` — add two package rows, add integration examples section |
| Modify | `docs/BACKLOG.md` — remove "Claude Code hook adapter" row |
