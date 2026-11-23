---
sidebar_position: 1
title: Claude Code
---

# Claude Code integration

`AI.Sentinel.ClaudeCode.Cli` is a native hook adapter for Anthropic's Claude Code CLI. It runs the AI.Sentinel detector pipeline against every prompt, tool call, and tool result without modifying your application — Claude Code invokes the hook via stdin/stdout per the [Claude Code hooks spec](https://docs.claude.com/en/docs/claude-code/hooks).

## Install

```bash
dotnet tool install -g AI.Sentinel.ClaudeCode.Cli
```

The CLI installs as `sentinel-hook` on your `PATH`, with no runtime configuration in your project. Installing needs the .NET 10 SDK. On linux-x64, linux-arm64, linux-musl-x64, linux-musl-arm64 (Alpine), osx-arm64 and win-x64, `dotnet tool install` picks the Native AOT build, which starts in a few milliseconds instead of paying ~190 ms of JIT startup on every hook call. Other platforms get a framework-dependent build that runs on the .NET 10 runtime.

A machine with an SDK older than .NET 10 can no longer install the tool. Install the .NET 10 SDK, or use the [release binary](#native-binary-without-the-net-sdk), which needs no .NET at all.

## Wire it into Claude Code

Edit `~/.claude/settings.json` (user-level) or `.claude/settings.json` (project-level):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "sentinel-hook user-prompt-submit" }] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "sentinel-hook pre-tool-use" }] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "sentinel-hook post-tool-use" }] }
    ]
  }
}
```

Three hook points:

| Hook | When it fires | What gets scanned |
|---|---|---|
| `UserPromptSubmit` | Every user message | The prompt text |
| `PreToolUse` | Before any tool call | Tool name + arguments |
| `PostToolUse` | After every tool call | Tool result text |

Restart Claude Code to pick up the new settings (or re-source the workspace).

## Severity → action

Both Claude Code and Copilot share the same env-var contract:

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_HIGH` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_LOW` | `Allow` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_VERBOSE` | `false` | `1` / `true` / `yes` → grep-friendly stderr diagnostic |
| `SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING` | `false` | `1` / `true` / `yes` → suppress the startup warning that semantic detection is inert. Set only after accepting that SEC-01 and SEC-05 will not fire |
| `SENTINEL_HOOK_REDACT` | `on` | `off` / `0` / `false` / `no` → turn off [redaction](#redaction) of tool output and the placeholder guard. Anything else, or unset, keeps them on |
| `SENTINEL_HOOK_HEADLESS` | `off` | `on` / `1` / `true` / `yes` → the run cannot ask the developer, so an `ask` outcome becomes a deny with instructions. Optional |
| `SENTINEL_HOOK_COMPLIANCE` | `off` | `on` / `1` / `true` / `yes` → run the four Art. 5 [compliance detectors](../detectors/compliance), which are off by default. Their findings warn instead of following `SENTINEL_HOOK_ON_HIGH`. Needs `SENTINEL_EMBEDDING_ENDPOINT`. Thresholds are code-only |
| `SENTINEL_HOOK_DETECTORS` | `security` | `security` → the [security preset](./mcp-proxy#detector-profiles) the MCP proxy uses: 16 security detectors plus the four Art. 5 compliance detectors, which run only with `SENTINEL_HOOK_COMPLIANCE=on`. `all` → every detector, including the operational and hallucination detectors that judge a model's reply and fire on tool output, see [Detectors](#detectors). Anything else, or unset, keeps `security` |
| `SENTINEL_HOOK_MAX_SCAN_BYTES` | `262144` | A positive integer → the scan budget, `SentinelOptions.MaxScanBytes`, in UTF-8 bytes. An event over it is blocked as [`SEC-00`](../detectors/overview#scan-budget-and-sec-00) under the default `SENTINEL_HOOK_ON_CRITICAL=Block`: a large tool result, and a large tool input too, so a `PreToolUse` for a write of a file over the budget is blocked before the tool runs; raise it to scan more. Anything else, or unset, keeps the default |
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |
| `SENTINEL_REVIEW_ENDPOINT` | — | Full chat completions URL of the second-stage reviewer, e.g. `https://api.openai.com/v1/chat/completions` or `http://localhost:11434/v1/chat/completions`. Without a reviewer, semantic detections are capped at Medium and only warn |
| `SENTINEL_REVIEW_MODEL` | — | Model identifier of the reviewer. Required with the endpoint |
| `SENTINEL_REVIEW_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_REVIEW_MAX_PER_SCAN` | `4` | Reviews per scan. `0` turns the review off |
| `SENTINEL_REVIEW_TIMEOUT_MS` | `5000` | Per-review timeout in milliseconds. A hook waits at most this long for the judge; lowering it trades recall on confirmed findings for latency |

**What the review endpoint receives.** `SENTINEL_REVIEW_ENDPOINT` is sent each flagged text, up to its last 64 KiB. That text can contain the secret or personal data a credential or PII detector flagged, just as the embedding endpoint receives the texts it embeds, so choose a provider you would trust with that data, or a local one. The reviewer's reason comes back the other way: it becomes part of the finding's reason, which the hook's block or warning text passes on to the model. It is sanitised to one line and capped at 200 characters.

### Detectors

The hook scans prompts, tool arguments and tool output, never a model's reply. So by default it runs the same security preset as the [MCP proxy](./mcp-proxy#detector-profiles): 16 of the 32 security detectors and the four compliance detectors. It leaves out the operational and hallucination detectors, which were written for a model's reply and fire as noise on tool traffic. Build logs and directory listings repeat lines, so `OPS-02` flags them. `OPS-11` rates a tool output more than 100 times the size of the tool call, or above 50,000 characters, as `High`, which blocks under the default `SENTINEL_HOOK_ON_HIGH=Block`. `SENTINEL_HOOK_DETECTORS=all` runs every detector.

**Behaviour change.** Until this preset, the hooks ran every detector. The default now also leaves out the 16 security detectors that are not in the preset, including the rule-based `SEC-32` SystemPromptEcho, which fires without an embedding endpoint. A hook that relied on any detector outside the preset needs `SENTINEL_HOOK_DETECTORS=all`.

### What each action does

The hook writes the output the [Claude Code hooks spec](https://docs.claude.com/en/docs/claude-code/hooks) documents:

- **`Block` on `UserPromptSubmit` or `PreToolUse`** → the hook exits 2 with the reason on stderr and writes nothing to stdout. Claude Code stops the prompt or the tool call and shows the reason.
- **`Block` on `PostToolUse`** → the tool has already run, so the hook exits 0 and withholds its output. stdout carries `"decision": "block"`, the reason, and an `updatedToolOutput` in place of the tool's output. See [Withheld output](#withheld-output).
- **`Warn`** → exit 0 with `{"systemMessage": "AI.Sentinel: <reason>"}` on stdout. Claude Code shows the message to the user.
- **`Allow`** → exit 0 with `{}` on stdout.

### Decision outcomes

A hook decision has one of five outcomes, strictest first: **deny**, **ask**, **guidance**, **allow** and **defer**. When several sources give an outcome for one call, the strictest wins. Today's severity actions map as `Block` to deny, `Warn` to guidance and `Allow` to defer, and the `SENTINEL_HOOK_ON_*` variables keep their values and their effect. A decision with an outcome carries a reason, the sources that caused it, a policy version (empty without a local policy) and where it was made, and the local audit records them as an `OUTCOME` entry. A severity action on its own writes no such entry and gives exactly the output described below.

**Allow never overrides the CLI's own permission prompt**: allow and defer emit no permission decision. Where the CLI cannot ask, or the run is headless, **ask** becomes **deny** with instructions: the agent is told to explain the command and why it is needed, then to let the developer run it or a policy owner allow it.

Every new setting here is optional and off by default.

How each outcome is expressed for Claude Code:

| Outcome | PreToolUse | UserPromptSubmit | PostToolUse |
|---|---|---|---|
| deny | exit 2, reason on stderr | exit 2, reason on stderr | `decision: "block"` and the withheld output |
| ask | `hookSpecificOutput.permissionDecision: "ask"` with the reason | deny with instructions | deny with instructions |
| guidance | `hookSpecificOutput.additionalContext`, the call runs | `additionalContext` | `additionalContext` |
| allow | `{}`, no permission decision | `{}` | `{}` |
| defer | `{}`, no permission decision | `{}` | `{}` |

The hook payload has no flag for a headless run, so a run that cannot ask is recognised by `permission_mode` `dontAsk`, which never prompts, or by `SENTINEL_HOOK_HEADLESS=on` (default off), for a run such as `claude -p`. With a severity action alone, `Warn` stays a `systemMessage`, as described above.

### Redaction

With `SENTINEL_HOOK_REDACT` on, the default, `PostToolUse` redacts personal data and secrets in the tool output. The hook returns the redacted output as `updatedToolOutput`, so the model sees `[EMAIL_1_k3f9x2]` in place of the address, together with an `additionalContext` note such as:

```text
AI.Sentinel redacted 1 EMAIL in this tool output. Placeholders such as [EMAIL_n_tag] stand for the real values; do not write them to files or commands.
```

The redaction is recorded as a `REDACTED` audit entry with counts only. The hook does not restore placeholders: the model keeps them for the rest of the session.

Not everything can be redacted. A command hook cannot rewrite the prompt on `UserPromptSubmit` or the tool arguments on `PreToolUse`, so a PII or credential finding there uses the action of its severity, and its audit summary ends with `; not redacted`. See [Redaction → Per surface](../redaction#per-surface).

**Placeholder guard.** Because the hook cannot restore a placeholder, writing one into a file or a command would replace the real value. On `PreToolUse`, the hook therefore denies a `Write`, `Edit`, `MultiEdit`, `NotebookEdit` or `Bash` call whose input contains text of the exact placeholder shape, such as `[EMAIL_1_k3f9x2]`, with exit 2 and a fixed reason that asks the model to get the value from the user. Ordinary text of that shape is denied too. `SENTINEL_HOOK_REDACT=off` disables the guard.

**When a tool rejects the output.** Claude Code checks `updatedToolOutput` against the tool's own output shape. Live checks with Claude Code 2.1.296 showed that `Read` accepts the redacted output, and that `Read` and `Bash` accept the withheld output. A built-in tool that rejects it has its original output shown to the model. The `additionalContext` note, which names the redacted types or the block reason, is then the only mitigation, and it does not hide the value.

### Withheld output

When a `PostToolUse` scan blocks, the output is withheld, also with `SENTINEL_HOOK_REDACT=off`. The withheld output keeps the shape of the tool's `tool_response`, because Claude Code rejects an output of another shape and then shows the original:

- identifier-like `type` values, such as `"type": "text"`, are kept;
- empty strings stay empty;
- numbers, booleans, nulls and property names are kept;
- every other string becomes `withheld by AI.Sentinel: <reason>`.

A first version also replaced `"type": "text"`. Claude Code rejected it and showed the original `Read` output, which is why `type` values are kept.

Set the env vars in your shell profile or directly in `settings.json`:

```json
{
  "env": {
    "SENTINEL_HOOK_ON_HIGH": "Block",
    "SENTINEL_HOOK_ON_MEDIUM": "Warn",
    "SENTINEL_HOOK_VERBOSE": "1"
  },
  "hooks": { /* ... */ }
}
```

## Local Rego policy

`SENTINEL_HOOK_POLICY_DIR` names a folder of [Rego](https://www.openpolicyagent.org/docs/policy-language) files. On every `PreToolUse` call the hook builds the [policy input](#tool-kinds-and-policy-input), evaluates the policy and acts on its outcome. This is the policy a PC uses without a server. **Every new setting here is optional and off by default: with `SENTINEL_HOOK_POLICY_DIR` unset, the hook behaves exactly as before.**

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_POLICY_DIR` | unset | A folder of `.rego` files in `package sentinel`. A subfolder is one bundle, and a file at the top is a bundle of its own. All files compile into one module |
| `SENTINEL_HOOK_POLICY_CACHE_DIR` | `ai-sentinel/policy-cache` under the user's local application data | Where the compiled policy is kept. Per user, and owner-only on Unix |

A bundle adds reasons to four sets, and the host combines them, strictest first:

```rego
package sentinel

import rego.v1

deny contains "recursive delete" if {
	input.kind == "shell"
	some c in input.details.shell.commands
	c.name == "rm"
	some a in c.args
	a in {"-rf", "-fr", "-r"}
}

deny contains sprintf("critical finding from %s", [f.detector]) if {
	some f in input.findings
	f.severity == "critical"
}

ask contains "git push needs a person" if {
	input.kind == "shell"
	some c in input.details.shell.commands
	c.name == "git"
	c.args[0] == "push"
}

guidance contains "prefer the gh CLI over the GitHub MCP server" if {
	input.kind == "mcp"
	input.details.mcp.server == "github"
}
```

`deny`, `ask`, `guidance` and `allow` are sets of reasons, and `severity_actions` sets an outcome per severity, see [Outcomes per severity](#outcomes-per-severity). The host defines `outcome`, `reasons` and `decision`, and reserves the folder name `_sentinel_host`; a policy that defines those names with another value fails when it runs, and the call is blocked. The input is the object of the section above: `kind`, `cli`, `tool`, `details`, `findings`, `repository`, `node` and `session`. A path is inside the repository when it lies under the working directory of the hook.

### Outcomes per severity

A policy can also set the outcome of a finding by severity, in place of or next to the `SENTINEL_HOOK_ON_*` variables. It adds entries to the set `severity_actions`, each with a `severity` and an `outcome`: severity `critical`, `high`, `medium` or `low` with `deny`, `ask`, `guidance`, `allow` or `defer`:

```rego
package sentinel

import rego.v1

severity_actions contains {"severity": "high", "outcome": "guidance"}
severity_actions contains {"severity": "medium", "outcome": "ask"}
severity_actions contains {"severity": "low", "outcome": "defer"}
```

Without a policy, or for a severity the policy leaves out, the variables work as they did: `Block` is deny, `Warn` is guidance and `Allow` is defer, and the built-in defaults are Block for Critical and High, Warn for Medium and Allow for Low. Where both set a severity, the **stricter wins**. A variable that is not set does not count: its built-in default applies only when the policy sets nothing for that severity, so a `severity_actions` entry of `guidance` for `high` with `SENTINEL_HOOK_ON_HIGH` unset gives guidance, while `SENTINEL_HOOK_ON_HIGH=Block` still gives deny. Policy outcomes that a hook decision cannot say, ask and allow, are carried as outcomes, so an ask is a real ask. A finding that a detector only alerts on is never stricter than guidance.

The rule is read once, before the scan, with an empty input, so it cannot depend on the tool call: write the per-call rules with `deny`, `ask`, `guidance` and `allow` as above. `severity_actions` is a set, so every bundle adds entries and none conflicts: when bundles set the same severity to different outcomes, the strictest wins, as everywhere else. A severity or outcome name that does not exist makes the call blocked as an internal error.

A [signed profile](#signed-policy-profile-groundwork-not-wired-in) carries severity defaults as `severity_defaults`, a severity name mapped to an action name. They are read the same way, so a profile and a policy can be combined with the strictest winning. The older action names are accepted there: `block` and `quarantine` are deny, `warn` and `alert` are guidance, and `log` and `passthrough` are defer. Nothing reads a profile yet. Every setting here is optional and off by default.

### How the outcome is combined

- The strictest outcome in the policy wins, and its reasons are the ones given. No rule gives **defer**: the policy has no opinion.
- The outcome of the policy and the outcomes of the other checks, the detectors, the approval rules and the placeholder guard, are combined by the same rule, so a block from a detector stays a block under a policy that allows.
- A shell command line that the parser marks `unparseable` gets at least **ask**, even when the policy returns **allow**. A policy **deny** stays a deny. Copilot CLI cannot ask, so there an ask is a deny with instructions, and a PowerShell command, which the parser never reads, always asks.
- The agent sees the reason of the rule. The local audit records the decision as an `OUTCOME` entry with the reason, the sources (`policy:<bundles>`, `builtin:<name>` for a refused builtin, `sentinel-checks`, `shell-parser`) and the policy version, which is the first 16 characters of the sha256 of the sources. The bundles listed are those of the folder, not the single rule.

### Compile, cache and speed

The policy is compiled once and cached, so a hook process loads native code instead of compiling. **The first call after a policy change compiles the folder in a child process**: the hook starts itself again to run the compiler, or starts the `opa` binary, and waits for it. That adds the start of a process to the compile, about 40 ms, on that one call. The compiler is a Go library, and a crash of it ends only the child, so a compiler that crashes, hangs for 30 seconds, fails or leaves no valid module blocks the call as an internal error; a crash in the hook itself would let Claude Code run the tool call. A cached module starts no process. The module and its native code are then cached under the hash of the sources, the Wasmtime version and the engine settings. After that the whole decision, from building the input to combining the outcome, takes a few milliseconds on a cached module, against a budget of 50 ms per call, and a test on the CI runners checks it. A change to any file gives a new module, and an old cache entry is never used.

The cache directory is per user and owner-only on Unix. Every cached file starts with the sha256 of the rest, and the hook checks it on the bytes it read before it loads them as native code. A missing or damaged file is rebuilt. The digest guards against damage and half-written files; it does not stop someone who can write to your cache directory, which is why the directory is yours alone. A cache directory that already exists and is open to other users, or on Windows has an ACL that allows them, is not trusted: the hook never reads, changes or empties it, because its entries could have been written by them and removing them in place would leave a window in which a second hook could load one. The cache then lives in a sibling directory named like the first with `.private` added, which is created owner-only in one step and used from then on, also after you make the first one private. The policy is compiled again there. If that sibling already exists and is open to others, the hook blocks and tells you.

### What a policy can use

- The compiler is given a capabilities document without `http.send`, `net.lookup_ip_addr` and `opa.runtime`, so a policy that uses one does not compile, and the error names it. A module that meets one at run time, for example one that was compiled elsewhere, denies the call with `builtin http.send reaches outside the process and is refused`.
- The OPA module runs most builtins itself. The host runs `sprintf` for the module, with the verbs `%s %v %d %f %e %g %q %t %x %X %o %b` and the width, precision and `-`, `+`, space and `0` flags. Any other builtin the module imports from its host denies the call and names it, such as `builtin uuid.rfc4122 is not implemented by the host`. The imports not yet run are `crypto.sha256`, `net.cidr_contains_matches`, `regex.find_n`, `regex.replace`, `semver.compare`, `time.now_ns`, `units.parse_bytes`, `urlquery.decode`, `uuid.rfc4122` and `yaml.unmarshal`.

### When the policy cannot be used

A folder that does not exist, holds no `.rego` file, does not compile, or uses a refused builtin blocks `PreToolUse` with exit 2 and `Sentinel internal error: policy '<folder>' could not be evaluated: <message>`, and an `AUTHZ-DENY` entry with the code `internal_error`. So does a policy that fails while it runs, a compiler process that crashes, times out or writes no valid module, and a machine with neither a compiler nor a cached module for the current policy. Nothing falls back to allowing the call. Other events do not read the policy.

Platforms:

- **Compiler.** The OpaDotNet interop compiler has a native library for linux-x64 and win-x64 only. On macOS, ARM and in a container that has no such library, the compiler is the `opa` binary, which has to be on the `PATH`; without it the first call after a policy change blocks with the reason that says so. A machine can also use a cache that was filled on another machine of the same platform and Wasmtime version.
- **Wasmtime.** Its native library has builds for linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64 and win-arm64, and none for musl. On Alpine, `SENTINEL_HOOK_POLICY_DIR` blocks every `PreToolUse` with a reason that names the platform, so leave it unset there.
- **Size.** The hook packages carry the Wasmtime library, about 30 MB, and on linux-x64 and win-x64 the compiler library, about 24 MB.

## Resident local process

`SENTINEL_HOOK_RESIDENT=on` lets the hooks use one resident process per user, started from the hook binary itself: `sentinel-hook --resident`, or `sentinel-copilot-hook --resident`, the same process for both. **It is optional and off by default. Every new setting here is optional and off by default: without `SENTINEL_HOOK_RESIDENT` no process is started, nothing is written to a state folder and the hooks behave exactly as before.** Setting `SENTINEL_HOOK_POLICY_DIR` does not turn it on, so a local policy keeps working as it did until you opt in.

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_RESIDENT` | `off` | `on` / `1` / `true` / `yes` → use the resident process |
| `SENTINEL_HOOK_RESIDENT_DIR` | `ai-sentinel/resident` under the user's local application data | The per-user state folder. Keep the path short: a Unix socket path is limited to about 100 characters |
| `SENTINEL_HOOK_RESIDENT_BUDGET_MS` | `15` | How long a hook waits for the resident process to answer before it evaluates in-process |

- **What it does.** It keeps the compiled policy module loaded and answers the policy evaluation of each `PreToolUse`, so a hook does not load the module itself. Its state folder is where the pause state and the signed profile cache are kept, once something writes them. It has no connection to a server yet, and forwards nothing.
- **Starting and stopping.** A hook that finds no resident process starts one, detached, with its standard streams not inherited, so the hook exits when it has decided; that call is evaluated in-process. A lock file opened without sharing in the state folder keeps it to one process per user, and the operating system releases the lock when the process ends, however it ends. On Linux and macOS the process calls `setsid` first, so it leaves the process group and session of the hook and survives a CLI that kills that group. On Windows nothing is done: .NET cannot start a process outside the job of its parent, so a CLI that runs hooks in a job that kills its members takes the resident process with it, and the next hook starts a new one. It exits after 30 idle minutes. No OS service is installed.
- **The channel.** A Unix domain socket in the state folder, which works on Linux, macOS and Windows 10 and later. The folder is private to the user (mode 700 on Unix, an ACL for the user alone on Windows) and the socket is mode 600, so another user cannot connect. A folder that already exists and is open to others is not used: the process moves to a `.private` sibling, as the policy cache does.
- **Evaluation order.** The resident process answers first. When it does not answer within the budget, or fails, the hook evaluates the module in-process; the budget is one for the whole call, shared by every evaluation of it, and it starts when the call is made. When that fails too the call is blocked as an internal error, as it is without the resident process, and once a server exists it is asked at that point. The whole decision aims at 50 ms per call, a target for a decision whose policy is cached and not a guarantee for every call: compiling a policy that is not cached can take up to 30 seconds, and the resident budget does not bound that.
- **Where a decision was made.** The audit entry of a decision that carries an outcome ends in `decided=resident`, `decided=in-process` or `decided=server`.
- **Pause state.** A hook reads the paused sessions from `pause.json` in the state folder. Nothing writes that file yet: the library can write it, but connecting a writer, so that a pause can be set through the resident process, comes later. The hook reads the file, with no network traffic and no running process, and denies every tool call of a paused session with the reason, whatever else it decided. A pause names a session and can have an end.
- **Profile cache.** The library can store the last valid signed profile as `profile.json`; nothing does so yet. It is stored only after the signature, the expiry, the organisation and the repository check as described under [Signed policy profile](#signed-policy-profile-groundwork-not-wired-in); a profile that fails does not replace the last valid one, and the cache is checked again on every read. Once a hook uses the cache, a cached profile will be used offline until it expires; that is future behaviour. Nothing sends the process a profile or pins keys yet, so no hook reads the cache; that comes with the sign-in and the server connection.
- **Files.** Every file is written whole under a temporary name and moved onto its name, with the sha256 of its content in front, so a reader sees the old file or the new one and never half of one; a damaged profile cache reads as absent. A pause file that exists but cannot be read or parsed does not read as "nobody is paused": every `PreToolUse` is blocked with `Sentinel internal error: InvalidDataException: the pause state is unreadable ...` and an `AUTHZ-DENY` entry with the code `internal_error`, until the file is rewritten. A pause file that does not exist means nothing is paused.
- **Fails closed.** A state folder that cannot be used blocks `PreToolUse` as an internal error. A resident process that is missing, slow or broken is not an error: the hook evaluates in-process.

## Which policy applies

The policy of a tool call comes from the node that owns the repository, not from the developer's team (ADR-232, ADR-246). `SENTINEL_HOOK_TEAM` does not exist. **Every new setting is optional and off by default: until a node map is cached in the state folder, which needs `SENTINEL_HOOK_RESIDENT=on` and an organisation's server, the policy input's `repository` and `node` stay empty and the hooks behave exactly as before.**

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_STRICT_REPOSITORY` | `on` | `off` / `0` / `false` / `no` → an unowned repository is not restricted. Applies only once a node map is cached |

- **The repository.** The git remote of the working directory, `origin` when there is one, else the first remote with a url. The hook reads `.git/config` itself and starts no `git` process. A `.git` file is followed: a worktree to the common folder that holds the config, a submodule to its own folder under the superproject, so a submodule reports its own remote.
- **The name.** The url is reduced to host and path in lower case, without scheme, port, credentials or `.git` suffix, so `git@github.com:Acme/Widgets.git` and `https://github.com/acme/widgets` are one repository. Nothing of the userinfo is kept, so a token embedded in a url reaches neither the policy input nor the audit.
- **The node.** The node map, the server's node configuration, is cached as `nodes.json` in the state folder and read with no network. A map that is cached and cannot be read blocks `PreToolUse` as an internal error rather than reading as "no node owns anything".
- **Strict repository mode.** On by default. A repository no node owns, or a folder outside git, gets only the organisation's top-level rules and sends no events. `sentinel-hook session-start`, run from the plugin's `SessionStart` hook, prints a message with that for the developer, and nothing for an owned repository or a PC without a node map. It applies whether or not `SENTINEL_HOOK_POLICY_DIR` is set; with no cached node map nothing changes.
- **Combining.** The organisation's top-level rules, the bundle of the owning node and a local `SENTINEL_HOOK_POLICY_DIR` are all evaluated, and the strictest outcome wins. A deny of the organisation holds in every repository, also where the bundle of the node allows the call, and the local folder can only tighten.
- **Not built yet.** Signing in to an organisation and the server's node configuration (#659, #664) fill the node map and the signed profiles; until then nothing in the shipped hooks writes them.

## When the hook itself fails

The hook fails closed on `PreToolUse`. When it cannot evaluate a tool call, it blocks the call with exit 2 and a reason that starts with `Sentinel internal error:` on stderr. This covers:

- a `SENTINEL_APPROVAL_CONFIG` that cannot be loaded or fails validation: `Sentinel internal error: approval config '<path>' could not be loaded: <message>`. Without this, one typo in the file would turn off every approval rule;
- an unexpected exception in the hook, for example an approval database that cannot be opened: `Sentinel internal error: <ExceptionType>: <message>`;
- input without a `tool_name`, while `SENTINEL_APPROVAL_CONFIG` has approval rules: `Sentinel internal error: PreToolUse input has no tool name`. Such a call cannot be checked against the rules. Without approval rules it is scanned as before;
- stdin that is empty or not valid JSON: `Sentinel internal error: malformed stdin JSON: <message>`, or `Sentinel internal error: empty stdin JSON: <message>` when stdin is the JSON `null`.

Tool calls stay blocked for as long as the cause persists. Fix the config file, or unset `SENTINEL_APPROVAL_CONFIG` to run without approval rules. The block is recorded in the [audit file](#audit-destination) as an `AUTHZ-DENY` entry with the code `internal_error` and the policy name `sentinel-internal`; when the input names no tool, the entry has the tool `unknown`, and for unreadable stdin also a new session id. If the hook times out or is killed, Claude Code does not treat that as a block: that behaviour belongs to Claude Code, not to Sentinel.

On `UserPromptSubmit` and `PostToolUse` the same failures exit 1 with the error on stderr. Claude Code shows it and goes on: exit 1 is not a block. A detector that fails, for example because the embedding endpoint is down, does not block on any event: it is skipped for that scan, reported on stderr, and the other detectors still run.

## Signed policy profile (groundwork, not wired in)

When the PC is later controlled by an organisation's server, it will enforce only policy the server signed (ADR-233). The building blocks are in the core library as internal types. No hook, setting or environment variable uses a profile yet, and every new setting this work adds is optional and off by default, so hook behaviour is unchanged. The [resident local process](#resident-local-process) can hold a verified profile in its state folder, but nothing hands it one.

- **Profile.** Organisation, repository, node, configuration version, module hash and module, `fail_mode`, severity defaults, logging switches, issue time and expiry.
- **Canonical form.** The server signs the profile as canonical JSON: one UTF-8 object with keys sorted by ordinal comparison, no whitespace, default System.Text.Json string escaping, integers in plain decimal and times as UTC to the whole second (`yyyy-MM-ddTHH:mm:ssZ`). The same profile always gives the same bytes.
- **Signature.** Ed25519 (RFC 8032) over those bytes. The .NET base library has no Ed25519, so the core package uses the managed BouncyCastle.Cryptography library: no native library per operating system, and it publishes under Native AOT without warnings on Windows, Linux and macOS.
- **Verification.** The plugin pins the server public keys at sign-in. It accepts a profile only when a pinned key signed it, or a pinned key endorsed the new key that did. It refuses, each with its own reason, an unknown key, a bad signature (including one changed byte), bytes that are not in canonical form, an expired profile, a profile for another organisation than the sign-in and a profile for another repository than the one asked for.
- **Lifetime.** 7 days by default; the organisation can set another lifetime. A cached profile is used offline until it expires. A cache that fails the signature check is unusable.
- **Keys.** The signing key reaches the server at startup through the deployment, as a base64 Ed25519 seed. It is never fetched at runtime and never stored (ADR-230). For a rotation the deployment passes the old and the new key side by side: profiles are signed by the new key and carry an endorsement of it by the old key, so plugins that pinned only the old key accept it and pin the new one. When every plugin has pinned the new key, the deployment drops the old one.

## Diagnostics — did the hook fire?

`SENTINEL_HOOK_VERBOSE=1` produces a stderr line on every invocation, including `Allow` outcomes:

```
[sentinel-hook] event=user-prompt-submit decision=Allow session=sess-42
[sentinel-hook] event=user-prompt-submit decision=Block detector=SEC-01 severity=Critical session=sess-42
```

Useful when wiring the hook for the first time ("did it actually run?") or when a block was expected but didn't happen. Leave off in steady state — Block and Warn already report their reason.

## Audit destination

The hook records to a local SQLite file by default, with no configuration. Every entry goes to `ai-sentinel/audit.db` under the per-user data folder: `~/.local/share` on Linux, `~/Library/Application Support` on macOS and `%LOCALAPPDATA%` on Windows.

- **What is recorded:** findings, authorization denials and approval holds. Allowed calls are not recorded.
- **Where it is shared:** the Copilot hook and the MCP proxy write to the same file, so one database holds everything your agents did. Several processes can write to it at once. Each entry's `Source` says which tool wrote it: `claude-code`, `copilot` or `mcp`.
- **Session id:** hook entries carry the session id Claude Code passes to the hook.
- **Permissions:** on Linux and macOS the directory is created `0700` and the files `0600`.
- **No data folder:** if the machine has no per-user data folder (for instance `HOME` is unset), recording is off and the hook reports a problem. Set `SENTINEL_HOOK_AUDIT_SQLITE` to a path to record anyway.
- **Chain:** the entries form a SHA-256 hash chain that continues across invocations. Browse and verify the file with [`sentinel dashboard`](#browse-the-audit-file).

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_AUDIT_SQLITE` | `<data folder>/ai-sentinel/audit.db` | A database path, or `off` (any case) to use the in-memory ring buffer and lose entries when the hook exits |
| `SENTINEL_HOOK_AUDIT_NDJSON` | — | A file path. Adds an NDJSON copy of every entry, next to the database |
| `SENTINEL_HOOK_AUDIT_MAX_MB` | `100` | Size cap in megabytes. `0` means no cap |

**Size cap.** The cap is enforced when the hook opens the file. Usage is measured in pages in use (pages minus free pages, times page size), not in file length, so it drops as soon as rows are deleted. The oldest entries are deleted in batches of 10% of the rows, at least 100, and one trim stops after at most 8 batches. A file far over the cap can therefore need more than one open to come under it. The hook never runs `VACUUM`, because that would hold the write lock for a long time, so the file stops growing at about the cap instead of shrinking.

**Failures never change a decision.** If the audit file cannot be opened or written, the hook still allows, warns or blocks exactly as it would have. On a `Block` that exits 2 the audit problem is not printed to stderr, because stderr carries the reason Claude Code feeds back to the model, unless `SENTINEL_HOOK_VERBOSE` is set. Otherwise it is printed with the prefix `[sentinel-hook] audit:`.

### NDJSON copy

```bash
export SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/claude-code.ndjson
```

One line per audit entry; ship via Filebeat/Vector. See [NDJSON file forwarder](../audit-forwarders/ndjson) for shipping recipes. Several hook processes, and the Copilot hook and MCP proxy, can share one NDJSON path: appends are serialised through a lock file, so no line is lost or interleaved.

### Browse the audit file

```bash
dotnet tool install -g AI.Sentinel.Cli
sentinel dashboard
```

`sentinel dashboard [--db <path>] [--port <port>]` serves the dashboard over the audit file at `http://127.0.0.1:5170/ai-sentinel/` by default. It listens on loopback unless `--bind` says otherwise, and does not open a browser. The other options (`--bind`, `--approval-config`, `--trusted-proxy`, `--user-header`, `--local-approver`) are in the [options table](../getting-started/dashboard#options). On start it prints `Audit chain intact: N entries` or `Audit chain broken at entry {id}`. It refuses a file that does not exist. Without an approval config it opens the file read-only and shows no approvals to act on: it never creates the file, never upgrades an older schema (run a hook or the MCP proxy once to upgrade it), and never appends. With a `sqlite` approval config (`--approval-config`, or `SENTINEL_APPROVAL_CONFIG`) it also lists pending requests and lets an approver approve or deny, and it opens the file writable so each decision is appended to the hash chain; see [the CLI dashboard as an approval host](../approvals/dashboard#the-cli-dashboard-as-an-approval-host). SQLite may create `-wal` and `-shm` files next to it. It needs the ASP.NET Core runtime, which the .NET SDK includes. The dashboard has a Source column and a `source` filter, so you can separate Claude Code, Copilot and MCP entries.

### Programmatic

For custom audit destinations or richer integration, reference the `AI.Sentinel.ClaudeCode` library directly in a C# host. Register AI.Sentinel and your own `IAuditStore` in DI, then hand the provider to `HookAdapter`:

```csharp
using AI.Sentinel.ClaudeCode;

var adapter = new HookAdapter(provider, HookConfig.FromEnvironment(env));
var input = new HookInput { SessionId = "sess-42", Prompt = "hello" };
HookOutput output = await adapter.HandleAsync(HookEvent.UserPromptSubmit, input, ct);
// output.Decision is Allow, Warn or Block; output.Reason explains a Warn or Block.
```

`provider` is an `IServiceProvider`, `env` an `IReadOnlyDictionary<string, string?>` and `ct` a `CancellationToken`. `HookConfig` is optional; without it the defaults apply.

Redaction is off in a `HookConfig` you build yourself, including the default one, so `PostToolUse` keeps the 3.0 behaviour: a secret in the tool output gives the severity decision, `Block` by default. `HookConfig.FromEnvironment`, as in the example, turns it on, as the CLI does, unless `SENTINEL_HOOK_REDACT` is off. To opt in on a config of your own, set `RedactToolResults = true`. On `PostToolUse` your host must then deliver `HookOutput.UpdatedToolOutput` instead of the original output: the redacted output on `Allow`, or on `Block` the withheld body that keeps the output's shape.

The decision follows the action your `SentinelOptions` give each detection: `Quarantine` maps through `HookConfig` by severity, `Alert` surfaces as `Warn`, or as `Allow` when `HookConfig` maps that severity to `Allow`, and `Log` gives `Allow`. The hook answers the most restrictive of these per-detection decisions, so a compliance `Warn` is kept when a `Low` finding mapped to `Allow` fires alongside it; the reason names the detection behind the decision, the higher severity on a tie. With a stock `AddAISentinel()`, a `High` finding is an `Alert` and so a `Warn`; the `sentinel-hook` CLI sets every severity to `Quarantine` so that `SENTINEL_HOOK_ON_*` decides.

Useful when you want a hook that ships entries to your own backend (Splunk, custom REST API, etc.) without going through file forwarders.

## Native binary without the .NET SDK

Every GitHub release carries the Native AOT builds as archives, for hosts that have no .NET SDK: `sentinel-hook-<version>-<rid>.tar.gz` for `linux-x64`, `linux-arm64`, `linux-musl-x64`, `linux-musl-arm64` and `osx-arm64`, and `sentinel-hook-<version>-win-x64.zip`. The glibc builds need glibc 2.28 or later, which covers every glibc distribution .NET 10 supports, RHEL 8 and SLES 15 included; the `linux-musl-*` builds are for Alpine. `sentinel-copilot-hook` and `sentinel-mcp` ship the same way. Each release also carries a `SHA256SUMS` file, and every archive has a GitHub build attestation that proves it was built by this repository's release workflow.

```bash
version=5.0.0
gh release download "v$version" --repo MarcelRoozekrans/AI.Sentinel \
  --pattern "sentinel-hook-$version-linux-x64.tar.gz" --pattern SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "sentinel-hook-$version-linux-x64.tar.gz" --repo MarcelRoozekrans/AI.Sentinel
sudo mkdir -p /opt/sentinel-hook
sudo tar -xzf "sentinel-hook-$version-linux-x64.tar.gz" --no-same-owner -C /opt/sentinel-hook
```

The archive holds the binary and the native SQLite library it loads from its own folder, so keep them together in their own directory. Point the hook `command` at the binary's full path instead of `sentinel-hook`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "/opt/sentinel-hook/sentinel-hook user-prompt-submit" }] }
    ]
  }
}
```

The binaries are not code-signed. `gh release download` and `curl` set no quarantine flag, but after a browser download macOS quarantines every extracted file: clear it with `xattr -dr com.apple.quarantine /opt/sentinel-hook`. On Windows, run `Unblock-File` on each extracted file after a browser download.

For a platform without a release build, publish one yourself: `dotnet publish src/AI.Sentinel.ClaudeCode.Cli -c Release -r <rid> -p:PublishAot=true`. This needs the native toolchain: the Visual Studio "Desktop development with C++" workload on Windows, `clang` and the `libc` dev packages on Linux, Xcode CLT on macOS.

## What gets blocked, in practice

With `SENTINEL_HOOK_ON_HIGH=Block` and a typical Claude Code workflow:

- **Prompt injection in user messages** (`SEC-01`) — blocked. The user said "ignore previous instructions"; the hook prevents Claude Code from acting on it.
- **Credential leaks and PII in tool results** — redacted. A tool returned a file containing an API key or an email address; PostToolUse replaces each value with a placeholder before Claude Code processes the result. With `SENTINEL_HOOK_REDACT=off` they follow their severity: an API key blocks and the output is withheld.
- **PII and credentials in prompts and tool arguments** — depends on severity, because these cannot be redacted. SSN/credit card → Block; phone numbers → Warn (default `OnMedium=Warn`).
- **Borderline jailbreaks** (`SEC-05`) — depends on cosine similarity. Exact-phrase matches block; loose paraphrases warn.
- **Repetitive or long tool output** — not flagged. The default [security preset](#detectors) leaves out `OPS-02` and `OPS-11`; with `SENTINEL_HOOK_DETECTORS=all`, repeated lines warn and output much larger than the tool call is withheld.

Tune via env vars to match your risk appetite.

## Tool kinds and policy input

The hook CLIs map each tool of the CLI onto one shared tool kind, so one policy rule can cover the same kind of tool in every CLI (ADR-235). This is the input that the policy work of the central server milestone evaluates against. It is read only when [`SENTINEL_HOOK_POLICY_DIR`](#local-rego-policy) is set, an optional setting that is off by default: without it the input is not built and the hooks behave exactly as before.

| Kind | Claude Code tools | Copilot CLI tools |
|---|---|---|
| `shell` | `Bash` | `bash`, `powershell` |
| `read` | `Read`, `NotebookRead` | `view` |
| `search` | `Glob`, `Grep`, `LS` | `glob`, `grep` |
| `write` | `Write` | `create` |
| `edit` | `Edit`, `MultiEdit`, `NotebookEdit` | `edit`, `str_replace_editor`, `apply_patch` |
| `fetch` | `WebFetch`, `WebSearch` | `web_fetch` |
| `mcp` | `mcp__<server>__<tool>` | `mcp__<server>__<tool>` |
| `agent` | `Task`, `Agent` | `task` |
| `other` | every other tool, such as `TodoWrite` | every other tool |

The input has `kind`, `cli` (`claude-code` or `copilot`), the CLI's own `tool` name, `details`, `findings` (`detector`, `severity`), `repository`, `node` and `session`. `repository` and `node` are empty until the issues that resolve them land. The details depend on the kind:

- `shell`: the command line parsed into commands with their arguments, assigned variable names and redirections, joined by `|`, `&&`, `||`, `;` or `&`, with quoting and escapes resolved and nothing expanded. A command line the parser cannot read with certainty, such as one with command substitution, a subshell, a here document, a compound command, the `time` keyword, a named descriptor redirection such as `{fd}>file`, a command name that needs expansion (`$X`, `${X}`, a glob, `~/bin/x`), the legacy `$[1+2]` arithmetic or an unterminated quote, is marked `unparseable` instead of guessed. The outcome for it is at least **ask**, also when the policy allows. PowerShell is always marked `unparseable`, because the parser reads POSIX quoting.
- `mcp`: `server`, `endpoint` and `tool`. The endpoint stays empty, because no hook payload carries it.
- `read`, `search`, `write`, `edit`: each path from the `file_path`, `path` or `notebook_path` argument, made absolute, with `in_repository` telling whether it lies inside the repository root. A path is kept as written, with `in_repository` false, when it starts with `~`, when it is relative and no repository root is known, or when the platform rejects it as a path. Paths are resolved lexically, symbolic links are not followed, and a path starting with `~` is never inside. Paths inside a Copilot `apply_patch` patch text are not read.
- `fetch`: the `url` argument.

The shell parser is checked in CI against a corpus of command lines with their expected parses, `tests/AI.Sentinel.Tests/Corpus/shell-commands.json`, so another parser can be tested against the same file.

## Programmatic use

The underlying library `AI.Sentinel.ClaudeCode` exposes `HookAdapter` and the vendor-agnostic `HookPipelineRunner` as public types. Reference the library package (not the `.Cli` tool package) to write your own host integration in C# — useful when you want to bundle AI.Sentinel inside a different agent framework or custom CLI.

## Next: [GitHub Copilot](./copilot) — same shape, different config file
