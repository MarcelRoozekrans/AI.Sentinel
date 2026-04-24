# New Detectors Design — OPS-09/10/11, SEC-18/19/21/22/30, HAL-09

**Date:** 2026-04-24  
**Approach:** Hybrid — rule-based for structural signals, rule-based + LLM escalation for behavioural signals, stub for infrastructure-dependent detector.

---

## Scope

Nine new detectors completing the backlog items listed under "New Detectors":

| ID | Class | Category | Strategy |
|---|---|---|---|
| OPS-09 | `TruncatedOutputDetector` | Operational | Rule-based |
| OPS-10 | `WaitingForContextDetector` | Operational | Rule-based |
| OPS-11 | `UnboundedConsumptionDetector` | Operational | Rule-based |
| SEC-18 | `ToolDescriptionDivergenceDetector` | Security | Stub |
| SEC-19 | `ToolCallFrequencyDetector` | Security | Partial rule-based + escalating |
| SEC-21 | `ExcessiveAgencyDetector` | Security | Rule-based + escalating |
| SEC-22 | `HumanTrustManipulationDetector` | Security | Rule-based + escalating |
| SEC-30 | `ShorthandEmergenceDetector` | Security | Rule-based + escalating |
| HAL-09 | `UncertaintyPropagationDetector` | Hallucination | Rule-based + escalating |

SEM-01 (`ShorthandEmergence`) and SEM-02 (`UncertaintyPropagation`) from the backlog are mapped to SEC-30 and HAL-09 respectively — no new `DetectorCategory` value needed.

---

## File Layout

```
src/AI.Sentinel/Detectors/
  Operational/
    TruncatedOutputDetector.cs
    WaitingForContextDetector.cs
    UnboundedConsumptionDetector.cs
  Security/
    ToolDescriptionDivergenceDetector.cs
    ToolCallFrequencyDetector.cs
    ExcessiveAgencyDetector.cs
    HumanTrustManipulationDetector.cs
    ShorthandEmergenceDetector.cs
  Hallucination/
    UncertaintyPropagationDetector.cs
```

---

## Detector Algorithms

### OPS-09 `TruncatedOutputDetector`

Inspect the last non-whitespace character of the assistant response.

- **Medium** — ends with a lowercase letter or comma (cut off mid-sentence)
- **Low** — ends with `...` or contains an unclosed code fence (odd number of ` ``` ` occurrences)
- **Clean** — otherwise

### OPS-10 `WaitingForContextDetector`

`[GeneratedRegex]` over the assistant response for stall phrases:
`"Please provide"`, `"Could you clarify"`, `"Could you share"`, `"I need more information"`, `"Could you specify"`, `"Can you tell me more"`.

Guard: only flag when the user message is ≥ 50 chars (filters legitimate clarification on genuinely short prompts).

- **Low** — one stall phrase match
- **Medium** — two or more stall phrase matches

### OPS-11 `UnboundedConsumptionDetector`

Compare assistant response char count (`responseLen`) to sum of all user message char counts (`promptLen`).

| Condition | Severity |
|---|---|
| `responseLen > 50_000` or ratio > 100× | High |
| `responseLen > 15_000` or ratio > 40× | Medium |
| `responseLen > 5_000` or ratio > 15× | Low |

### SEC-18 `ToolDescriptionDivergenceDetector` — Stub

Extends `StubDetector("SEC-18", DetectorCategory.Security)`.  
Returns `Clean` immediately. Needs tool descriptor snapshot in `SentinelContext` (v1.1 follow-up) before a rule-based implementation is possible. Marked `ILlmEscalatingDetector` via `StubDetector` for the rare case where a divergent description leaks into message text.

### SEC-19 `ToolCallFrequencyDetector`

Count `ChatRole.Tool` messages in `ctx.Messages`. Implements `ILlmEscalatingDetector`.

| Tool message count | Severity |
|---|---|
| > 20 | High |
| > 10 | Medium |
| > 5 | Low |

### SEC-21 `ExcessiveAgencyDetector`

`[GeneratedRegex]` over assistant response for autonomous-action phrases:
`"I have written"`, `"I have created"`, `"I have deleted"`, `"I have sent"`, `"I deployed"`, `"I executed"`, `"I modified"`, `"I ran"`, `"I spawned"`, `"wrote to"`, `"uploaded to"`.

- **High** — match on a destructive verb: `deleted`, `deployed`, `spawned`
- **Medium** — any other match

Implements `ILlmEscalatingDetector`.

### SEC-22 `HumanTrustManipulationDetector`

`[GeneratedRegex]` for rapport and authority patterns:
- Rapport: `"you can trust me"`, `"I care about you"`, `"as your friend"`, `"I'm on your side"`, `"only I understand"`
- Authority: `"I am your"` + authority noun (`assistant|advisor|guardian|protector`)

- **High** — authority-impersonation pattern
- **Medium** — rapport pattern

Implements `ILlmEscalatingDetector`.

### SEC-30 `ShorthandEmergenceDetector`

Count distinct all-caps tokens ≥ 3 chars that are not on a common-acronym allowlist (`API`, `JSON`, `HTTP`, `URL`, `SDK`, `CLI`, `AI`, `LLM`, `MCP`, `REST`, `SQL`, `XML`, `CSV`, `JWT`, `UUID`).

- **Medium** — ≥ 5 unknown all-caps tokens
- **Low** — ≥ 3 unknown all-caps tokens

Implements `ILlmEscalatingDetector` — the LLM escalation pass carries the weight for subtle emergent language patterns.

### HAL-09 `UncertaintyPropagationDetector`

Two regex passes over the assistant response:

1. **Hedging phrases:** `"I think"`, `"I believe"`, `"possibly"`, `"probably"`, `"might be"`, `"it seems"`, `"perhaps"`, `"not certain"`
2. **Definitive assertions:** `"the answer is"`, `"it is"`, `"this means"`, `"therefore"`, `"in fact"`, `"certainly"`

- **Medium** — hedging phrase AND definitive assertion both present (uncertainty promoted to fact in same response)
- **Low** — hedging phrase present only

Implements `ILlmEscalatingDetector`.

---

## Registration Changes

Every new detector carries `[Singleton(As = typeof(IDetector), AllowMultiple = true)]` — source-gen handles DI automatically.

Two manual updates required:
1. `McpPipelineFactory.BuildAllDetectors()` — add all 9 instances
2. `McpDetectorPreset.Security` preset — add SEC-19, SEC-21, SEC-22, SEC-30 (all are `DetectorCategory.Security`)

The drift test (`McpPipelineFactoryTests`) will fail if either list is incomplete — acts as a compile-time guard.

---

## Test Coverage

All tests follow the `SentinelContext Ctx(string text)` / `CtxMessages(...)` helper pattern from existing test files.

| Detector | Test cases |
|---|---|
| OPS-09 | `MidSentence_Medium`, `OpenCodeFence_Low`, `CompleteResponse_Clean` |
| OPS-10 | `ShortUserMsg_Clean`, `LongUserSelfContained_Low`, `MultipleStalls_Medium` |
| OPS-11 | `SmallResponse_Clean`, `LargeAbsolute_Low`, `HighRatio_Medium` |
| SEC-18 | `ReturnsClean` (stub contract) |
| SEC-19 | `FewCalls_Clean`, `ExcessiveCalls_Medium` |
| SEC-21 | `NeutralResponse_Clean`, `SoftVerb_Medium`, `DestructiveVerb_High` |
| SEC-22 | `Neutral_Clean`, `Rapport_Medium`, `AuthorityImpersonation_High` |
| SEC-30 | `CommonAcronyms_Clean`, `ThreeUnknownTokens_Low`, `FiveUnknownTokens_Medium` |
| HAL-09 | `NoHedging_Clean`, `HedgingOnly_Low`, `HedgingPlusAssertion_Medium` |

Stub and escalating detectors are also included in the relevant `AllXxxStubDetectors_DoNotThrow` smoke-test groups.
