---
sidebar_position: 4
title: Codex CLI
---

# Codex CLI integration

`AI.Sentinel.Codex.Cli` is a native hook adapter for the lifecycle hooks of OpenAI's Codex CLI. It does what [`sentinel-hook`](./claude-code) does for Claude Code: the same detectors, approval config, local audit, severity settings, local Rego policy, decision outcomes and fail-closed behaviour. Codex's hook payloads and output follow the Claude Code shape closely, so most of that page applies unchanged. This page lists what differs.

**Every new setting here is optional and off by default.** The adapter adds no setting of its own; it reads the `SENTINEL_HOOK_*`, `SENTINEL_APPROVAL_CONFIG`, `SENTINEL_EMBEDDING_*` and `SENTINEL_REVIEW_*` variables the other hooks read.

## Sources

This page follows the Codex documentation, not memory of it:

- [Codex hooks](https://developers.openai.com/codex/hooks) (Markdown: `https://developers.openai.com/codex/hooks.md`): events, matchers, stdin fields, output fields, exit codes and the tool coverage table.
- [`docs/config.md` in openai/codex](https://github.com/openai/codex/blob/main/docs/config.md#lifecycle-hooks): managed hooks.
- The hook engine in [`codex-rs/hooks`](https://github.com/openai/codex/tree/main/codex-rs/hooks), `src/events/pre_tool_use.rs` and `src/engine/output_parser.rs`, for what a `PreToolUse` hook that exits with another code than 0 or 2 does.

Codex's own page says its tool hooks are "a useful guardrail, not a complete enforcement boundary": hosted tools such as `WebSearch` do not run hooks, and some specialized tool paths can opt out. A call Codex does not send to the hook cannot be blocked by it.

## Install

```bash
dotnet tool install -g AI.Sentinel.Codex.Cli
```

The CLI installs as `sentinel-codex-hook` on your `PATH`. As with the other hooks, installing needs the .NET 10 SDK, and the Native AOT build is picked on linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64 (Alpine), osx-arm64 and win-x64. Each GitHub release also carries `sentinel-codex-hook-<version>-<rid>` archives, listed in `SHA256SUMS` with a build-provenance attestation; see [Claude Code → Native binary without the .NET SDK](./claude-code#native-binary-without-the-net-sdk).

## Wire it into Codex

Add to `~/.codex/hooks.json`, or `.codex/hooks.json` in a trusted project:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "sentinel-codex-hook user-prompt-submit", "timeout": 10 }] }
    ],
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "sentinel-codex-hook pre-tool-use", "timeout": 45 }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "sentinel-codex-hook post-tool-use", "timeout": 10 }] }
    ]
  }
}
```

The same hooks can be declared inline under `[[hooks.PreToolUse]]` in `config.toml`; use one format per layer. Omit `matcher` so every tool is scanned. `timeout` is in seconds. Keep the `PreToolUse` timeout above 30 s plus the review timeout and scan time, for the reason given on the [Copilot page](./copilot#wire-it-into-copilot): a hook that is cut off by the host does not block.

**Codex asks you to trust the hook.** A non-managed hook does not run until you review it with `/hooks`, and a changed command needs a new review. Until then nothing is scanned. A managed hook, from `requirements.toml` or the system `hooks.json`, is trusted by policy and cannot be disabled by the user; use it where the scan must not be optional.

### Events covered

| Codex event | Verb | Covered | What gets scanned |
|---|---|---|---|
| `PreToolUse` | `pre-tool-use` | yes | Tool name and `tool_input`: `Bash`, `apply_patch`, MCP tools and other local function tools |
| `UserPromptSubmit` | `user-prompt-submit` | yes | The prompt text |
| `PostToolUse` | `post-tool-use` | yes | The tool call and `tool_response` |
| `PermissionRequest` | none | no | Codex runs it only when it is about to ask for approval. Not needed: `PreToolUse` sees every call |
| `SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `Stop`, `Interrupt`, `PreCompact`, `PostCompact`, `PreModelRequest`, `PostModelRequest` | none | no | Not tool calls or prompts |

An unknown verb prints the usage and exits 1.

## Decision outcomes

A hook decision has one of five outcomes, strictest first: **deny**, **ask**, **guidance**, **allow** and **defer**; the strictest wins. The mapping of the severity actions and the outcome audit are described on the [Claude Code page](./claude-code#decision-outcomes). What Codex can express:

| Outcome | `PreToolUse` and `UserPromptSubmit` | `PostToolUse` |
|---|---|---|
| deny | exit 2, reason on stderr: Codex blocks the call or the prompt | `decision: "block"` with the reason on stdout, exit 0: Codex replaces the tool result with that feedback. The tool already ran |
| ask | Codex cannot ask from a hook: `permissionDecision: "ask"` is parsed but unsupported, and Codex would run the call. So it is a **deny with instructions**, as when a run is headless | deny with instructions |
| guidance | `hookSpecificOutput.additionalContext`, exit 0: added for the model as developer context | the same |
| allow | `{}`, no permission decision, so Codex's own approval flow still applies | the same |
| defer | `{}` | the same |

A `Warn` from a severity action is `{"systemMessage":"AI.Sentinel: <reason>"}`, which Codex shows as a warning. `SENTINEL_HOOK_HEADLESS` has no effect: a Codex hook never asks.

**An exit 2 always carries a reason.** Codex blocks on exit 2 only when stderr holds a reason; with none it reports a failed hook and runs the call. The hook writes `AI.Sentinel blocked this call.` when a decision has no text of its own.

## Redaction is off

Codex cannot replace a tool result or a prompt from a command hook: `updatedMCPToolOutput` is parsed but unsupported, and a `PostToolUse` block only replaces the result with feedback. So `sentinel-codex-hook` never redacts, whatever `SENTINEL_HOOK_REDACT` says, and a finding in a tool result uses the action of its severity, a block by default. For the same reason the placeholder guard, which only matters after a redaction, is off.

## Severity, approvals, audit and policy

- **Severity settings** (`SENTINEL_HOOK_ON_CRITICAL`, `ON_HIGH`, `ON_MEDIUM`, `ON_LOW`, `SENTINEL_HOOK_VERBOSE`, `SENTINEL_HOOK_DETECTORS`, `SENTINEL_HOOK_COMPLIANCE`, `SENTINEL_HOOK_MAX_SCAN_BYTES`, the embedding and review variables): as on the [Claude Code page](./claude-code). The diagnostic line is prefixed `[sentinel-codex-hook]`.
- **Approval config** (`SENTINEL_APPROVAL_CONFIG`): rules are keyed by the tool name Codex reports, such as `Bash` or `mcp__server__tool`.
- **Local audit**: findings, denials and approval holds are recorded to the shared SQLite file, with `Source` set to `codex`. The variables are the same three: `SENTINEL_HOOK_AUDIT_SQLITE`, `SENTINEL_HOOK_AUDIT_NDJSON`, `SENTINEL_HOOK_AUDIT_MAX_MB`.
- **Local Rego policy** (`SENTINEL_HOOK_POLICY_DIR`): evaluated on every `PreToolUse`; the input has `cli` set to `codex`. A policy that cannot be loaded blocks the call.

## Tool kinds

Codex tool names map onto the shared tool kinds, as the Claude Code and Copilot names do. The policy input is on the [Claude Code page](./claude-code#tool-kinds-and-policy-input).

| Codex tool | Kind | Details in the policy input |
|---|---|---|
| `Bash` (shell commands and unified exec) | `shell` | The parsed command line |
| `apply_patch` | `edit` | The file headers of the patch in `tool_input.command`. `Edit` and `Write` are matcher aliases only: the hook input always reports `apply_patch` |
| `mcp__<server>__<tool>` | `mcp` | Server and tool |
| `spawn_agent`, `Agent` | `agent` | none |
| any other local function tool, such as `update_plan` | `other` | none |

Codex has no separate read, search or fetch tool for the hook: those go through `Bash` or an MCP tool, and hosted tools such as `WebSearch` do not run hooks.

## When the hook itself fails

The hook fails closed on `PreToolUse`, exactly as `sentinel-hook` does. When it cannot evaluate a call it exits 2 with a reason that starts with `Sentinel internal error:` on stderr, and Codex blocks the call. This covers an approval config that cannot be loaded, a policy that cannot be loaded, unreadable stdin, a missing tool name while approval rules are set, and any unexpected exception. The block is audited as an `AUTHZ-DENY` entry with the code `internal_error`.

This matters more for Codex than for other hosts: **any other non-zero exit code, and a crash, is a failed hook that Codex reports and then continues with the tool call.** Only exit 2 with a reason blocks. On `UserPromptSubmit` and `PostToolUse` a failure exits 1 with the error on stderr, which Codex does not treat as a block.

## Next: [Claude Code](./claude-code), [GitHub Copilot](./copilot), [MCP proxy](./mcp-proxy)
