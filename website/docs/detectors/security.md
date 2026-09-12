---
sidebar_position: 2
title: Security detectors
---

# Security detectors (31)

The security category covers prompt injection, jailbreaks, credential / PII leakage, covert channels, indirect injection, and RAG poisoning. These are the highest-priority detectors for any production deployment.

## Reference

| ID | Detector | Type | Detects |
|---|---|---|---|
| **SEC-01** | `PromptInjectionDetector` | Rule + Semantic ⚠️ | Override / injection phrase patterns. The unambiguous phrasings are matched by rule and need no generator; paraphrases need one |
| **SEC-02** | `CredentialExposureDetector` | Rule-based | API keys, tokens, private keys, secrets in output |
| **SEC-03** | `ToolPoisoningDetector` | Semantic ⚠️ | Suspicious tool-call manipulation patterns |
| **SEC-04** | `DataExfiltrationDetector` | Semantic ⚠️ | Base64 blobs, high-entropy encoded data |
| **SEC-05** | `JailbreakDetector` | Rule + Semantic ⚠️ | Jailbreak attempt phrases. Unambiguous ones (`DAN mode`, `unrestricted AI mode`) are matched by rule; roleplay exploits need a generator |
| **SEC-06** | `PrivilegeEscalationDetector` | Semantic ⚠️ | Role / permission escalation requests |
| **SEC-07** | `CovertChannelDetector` | Semantic ⚠️ | Encoding-based hidden payloads |
| **SEC-08** | `EntropyCovertChannelDetector` | Stub | Statistical entropy anomalies in output — **not implemented; always returns `Clean`** |
| **SEC-09** | `IndirectInjectionDetector` | Semantic ⚠️ | Injection via retrieved documents or tool results |
| **SEC-10** | `AgentImpersonationDetector` | Semantic ⚠️ | Model claiming to be a different agent or system |
| **SEC-11** | `MemoryCorruptionDetector` | Semantic ⚠️ | Attempts to corrupt agent memory / context |
| **SEC-12** | `UnauthorizedAccessDetector` | Semantic ⚠️ | Attempts to access restricted resources |
| **SEC-13** | `ShadowServerDetector` | Semantic ⚠️ | Redirection to unauthorised endpoints |
| **SEC-14** | `InformationFlowDetector` | Semantic ⚠️ | Cross-context data leakage |
| **SEC-15** | `PhantomCitationSecurityDetector` | Semantic ⚠️ | Security-context hallucinated authority sources |
| **SEC-16** | `GovernanceGapDetector` | Semantic ⚠️ | Policy / compliance bypass attempts |
| **SEC-17** | `SupplyChainPoisoningDetector` | Semantic ⚠️ | Compromised dependency suggestions |
| **SEC-18** | `ToolDescriptionDivergenceDetector` | Stub | Tool description changed at runtime vs. original declaration — **not implemented; always returns `Clean`** (requires a tool-descriptor snapshot) |
| **SEC-19** | `ToolCallFrequencyDetector` | Rule-based | Counts `ChatRole.Tool` messages; flags sessions with excessive tool invocations |
| **SEC-20** | `SystemPromptLeakageDetector` | Semantic ⚠️ | Requests to reveal the system prompt or hidden instructions. Does **not** detect the system prompt itself appearing in output — it has no copy to compare against |
| **SEC-21** | `ExcessiveAgencyDetector` | Semantic ⚠️ | Autonomous-action language ("I deleted", "I deployed", "I executed") |
| **SEC-22** | `HumanTrustManipulationDetector` | Semantic ⚠️ | Rapport / authority manipulation ("you can trust me", "I am your advisor") |
| **SEC-23** | `PiiLeakageDetector` | Rule-based | PII: SSN, credit card, IBAN, BSN, UK NINO, passport, DE tax ID, email + name, phone, DOB |
| **SEC-24** | `AdversarialUnicodeDetector` | Rule-based | Zero-width spaces, homoglyphs, invisible characters used to smuggle hidden instructions |
| **SEC-25** | `CodeInjectionDetector` | Semantic ⚠️ | SQL injection, shell metacharacters, path traversal in LLM-generated code |
| **SEC-26** | `PromptTemplateLeakageDetector` | Semantic ⚠️ | Prompt scaffolding markers — `{{variable}}`, `<SYSTEM>`, `[INST]` |
| **SEC-27** | `LanguageSwitchAttackDetector` | Semantic ⚠️ | Abrupt script / language switch mid-response — injection vector via non-Latin text |
| **SEC-28** | `RefusalBypassDetector` | Semantic ⚠️ | Model complied with a request it should have refused (caller-supplied forbidden patterns) |
| **SEC-29** | `OutputSchemaDetector` | Rule-based | Response doesn't deserialize as the caller-supplied `ExpectedResponseType` (OWASP LLM05). **Inactive unless** `SentinelOptions.ExpectedResponseType` *and* an `ISerializerDispatcher` are supplied — neither is registered by default |
| **SEC-30** | `ShorthandEmergenceDetector` | Semantic ⚠️ | Unknown all-caps tokens that may signal emergent covert language |
| **SEC-31** | `VectorRetrievalPoisoningDetector` | Semantic ⚠️ | Malicious instructions embedded in RAG-retrieved document chunks (OWASP LLM08) |

## Severity ranges

The severity each detector emits depends on what fires:

- **Rule-based detectors** typically pin to one or two severities per pattern class. `PiiLeakageDetector` for example emits `Critical` for credit cards / SSNs, `High` for IBANs, `Medium` for emails+name, `Low` for phone numbers.
- **Semantic detectors** emit `High` / `Medium` / `Low` based on cosine similarity against their reference example sets, with thresholds at 0.90 / 0.82 / 0.75 by default. Override by subclassing and setting `HighThreshold` / `MediumThreshold` / `LowThreshold` overrides.
- **LLM-escalation detectors** start with a rule-based hit and ask a second-pass LLM classifier to confirm or downgrade the severity.

## Tuning specific detectors

A few detectors expose configuration knobs beyond the universal Floor/Cap:

- **`SEC-23 PiiLeakage`** — `IncludePhoneNumbers` / `IncludeDateOfBirth` etc. (planned; today the detector emits all PII patterns it knows about; clamp via `Configure<T>(c => c.SeverityCap = Severity.Low)` to suppress noisy classes).
- **`SEC-19 ToolCallFrequency`** — threshold for "excessive" calls (default 10 per session). Subclass to override.
- **`SEC-29 OutputSchema`** — the expected type comes from `SentinelOptions.ExpectedResponseType`, and an `ISerializerDispatcher` must be supplied to the detector. The library registers neither, so SEC-29 returns `Clean` until both are configured.

For everything else, the universal pattern is:

```csharp
opts.Configure<JailbreakDetector>(c =>
{
    c.Enabled = true;                       // already the default
    c.SeverityFloor = Severity.High;        // promote any firing to High+
    c.SeverityCap   = Severity.Critical;    // pass-through Critical unchanged
});
```

## OWASP LLM Top 10 (2025) Coverage

| OWASP LLM | Detectors | Fires by default |
|---|---|---|
| **LLM01** Prompt Injection | SEC-01, SEC-05, SEC-09, SEC-03 | ⚠️ partial (2/4) |
| **LLM02** Sensitive Information Disclosure | SEC-02, SEC-23, SEC-04, SEC-14 | ⚠️ partial (2/4) |
| **LLM03** Supply Chain | SEC-17 | ❌ none |
| **LLM04** Data & Model Poisoning | (out of scope — poisoning happens at training or fine-tuning time and is not observable at inference; see LLM08 for retrieval-time poisoning) | — |
| **LLM05** Improper Output Handling | SEC-25, SEC-29 | ❌ none |
| **LLM06** Excessive Agency | SEC-21, SEC-19 | ⚠️ partial (1/2) |
| **LLM07** System Prompt Leakage | SEC-20, SEC-26, SEC-16 | ❌ none |
| **LLM08** Vector & Embedding Weaknesses | SEC-31 | ❌ none |
| **LLM09** Misinformation | HAL-01, HAL-08, HAL-06, HAL-09, HAL-04, HAL-05 | ❌ none |
| **LLM10** Unbounded Consumption | OPS-11, OPS-02 | ✅ yes |

> **Fires by default** counts only detectors active in a stock `AddAISentinel()` install. Semantic detectors need an `EmbeddingGenerator`, and stubs never fire at all — so a row marked ❌ has no active control until you configure one. Five of the nine in-scope categories are in that state out of the box. **LLM01 Prompt Injection** is not one of them: `SEC-01` and `SEC-05` carry a rule layer that fires without a generator.
