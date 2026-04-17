# AI.Sentinel Feature Backlog

Items are grouped by theme. No priority order implied within a group.

---

## New Detectors

### Operational

| ID (proposed) | Name | What it detects |
|---|---|---|
| OPS-09 | `TruncatedOutputDetector` | Response cut off mid-sentence — model ran out of tokens or was interrupted |
| OPS-10 | `WaitingForContextDetector` | Model stalling with placeholder phrases ("Please provide...", "Could you clarify...") when the request was self-contained |
| OPS-11 | `UnboundedConsumptionDetector` | Abnormally large response length or token-count anomaly relative to the prompt — possible resource exhaustion or runaway generation (cf. OWASP LLM10) |

### Security

| ID (proposed) | Name | What it detects |
|---|---|---|
| SEC-18 | `ToolDescriptionDivergenceDetector` | Tool description observed at invocation differs from description at discovery — possible MCP supply-chain manipulation |
| SEC-19 | `ToolCallFrequencyDetector` | Anomalous spike or unusual pattern in tool invocation rate within a session — possible automated exfiltration or resource abuse |
| SEC-20 | `SystemPromptLeakageDetector` | Response contains verbatim fragments of the system prompt — model was manipulated into disclosing its instructions (cf. OWASP LLM07) |
| SEC-21 | `ExcessiveAgencyDetector` | Model takes unsolicited autonomous actions (file writes, API calls, spawning agents) beyond its stated scope (cf. OWASP LLM06 / ASI02) |
| SEC-22 | `HumanTrustManipulationDetector` | Model output attempts to build false rapport, impersonate an authority figure, or exploit human-agent trust to bypass oversight (cf. OWASP ASI09) |

### Multi-Agent / Semantic

| ID (proposed) | Name | What it detects |
|---|---|---|
| SEM-01 | `ShorthandEmergenceDetector` | Agents developing a private shorthand or code language between them not present in the original instructions |
| SEM-02 | `UncertaintyPropagationDetector` | Speculative or partial results ("I think...", "possibly...") promoted to stated facts as they pass between agents |

---

## Intervention Engine

| Feature | Description |
|---|---|
| `SentinelAction.Reroute` | New intervention level: redirect the message to a fallback agent instead of quarantining or logging. Requires a configured `FallbackClient`. |

---

## Architecture / Integration

| Feature | Description |
|---|---|
| **Claude Code hook adapter** | `AI.Sentinel.ClaudeCode` package — emit `PreToolUse` / `PostToolUse` hook payloads from the audit store so Claude Code can block or annotate tool calls in the IDE |
| **Multi-agent spawn-chain tracking** | Propagate a `TraceId` through nested `SentinelChatClient` instances so the audit store records a parent→child call graph. Enables cross-agent contradiction and uncertainty propagation detection. |
| **Session behavioral signatures** | Derive a compact fingerprint per session (tool call distribution, message length variance, vocabulary entropy) for anomaly scoring against a rolling baseline |
| **Streaming pipeline support** | Run detector passes on `GetStreamingResponseAsync` — currently only `GetResponseAsync` is scanned |
| **Output schema validation** | Validate structured (JSON/XML) responses against a caller-supplied schema before returning to the application — catches malformed outputs and prompt-injected schema violations (cf. OWASP LLM05) |
| **Per-session rate limiting** | Circuit breaker that triggers `SentinelAction` when call rate within a session window exceeds a configurable threshold — guards against token-budget exhaustion and automated enumeration attacks (cf. OWASP LLM10) |

---

## Dashboard (`AI.Sentinel.AspNetCore`)

| Feature | Description |
|---|---|
| Per-session timeline view | Show the full prompt/response scan sequence for a single session, not just the global feed |
| Detector hit rate sparklines | Small per-detector trend charts over the last N minutes |
| Export audit log | Download the current ring buffer as NDJSON from the dashboard |
