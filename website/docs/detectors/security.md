---
sidebar_position: 2
title: Security detectors
---

# Security detectors (31)

The security category covers prompt injection, jailbreaks, credential / PII leakage, covert channels, indirect injection, and RAG poisoning. These are the highest-priority detectors for any production deployment.

## Reference

| ID | Detector | Type | Detects |
|---|---|---|---|
| **SEC-01** | `PromptInjectionDetector` | Rule-based | Override / injection phrase patterns (`ignore all previous instructions`, `you are now a different AI`, etc.) |
| **SEC-02** | `CredentialExposureDetector` | Rule-based | API keys, tokens, private keys, secrets in output |
| **SEC-03** | `ToolPoisoningDetector` | Rule-based | Suspicious tool-call manipulation patterns |
| **SEC-04** | `DataExfiltrationDetector` | Rule-based | Base64 blobs, high-entropy encoded data |
| **SEC-05** | `JailbreakDetector` | Rule-based | Jailbreak attempt phrases (DAN, roleplay exploits) |
| **SEC-06** | `PrivilegeEscalationDetector` | Rule-based | Role / permission escalation requests |
| **SEC-07** | `CovertChannelDetector` | Semantic | Encoding-based hidden payloads |
| **SEC-08** | `EntropyCovertChannelDetector` | LLM escalation | Statistical entropy anomalies in output |
| **SEC-09** | `IndirectInjectionDetector` | Semantic | Injection via retrieved documents or tool results |
| **SEC-10** | `AgentImpersonationDetector` | Semantic | Model claiming to be a different agent or system |
| **SEC-11** | `MemoryCorruptionDetector` | Semantic | Attempts to corrupt agent memory / context |
| **SEC-12** | `UnauthorizedAccessDetector` | Semantic | Attempts to access restricted resources |
| **SEC-13** | `ShadowServerDetector` | Semantic | Redirection to unauthorised endpoints |
| **SEC-14** | `InformationFlowDetector` | Semantic | Cross-context data leakage |
| **SEC-15** | `PhantomCitationSecurityDetector` | Semantic | Security-context hallucinated authority sources |
| **SEC-16** | `GovernanceGapDetector` | Semantic | Policy / compliance bypass attempts |
| **SEC-17** | `SupplyChainPoisoningDetector` | Semantic | Compromised dependency suggestions |
| **SEC-18** | `ToolDescriptionDivergenceDetector` | Stub | Tool description changed at runtime vs. original declaration (requires tool-descriptor snapshot) |
| **SEC-19** | `ToolCallFrequencyDetector` | Rule-based | Counts `ChatRole.Tool` messages; flags sessions with excessive tool invocations |
| **SEC-20** | `SystemPromptLeakageDetector` | Rule-based | Verbatim fragments of the system prompt echoed in conversation history |
| **SEC-21** | `ExcessiveAgencyDetector` | Semantic | Autonomous-action language ("I deleted", "I deployed", "I executed") |
| **SEC-22** | `HumanTrustManipulationDetector` | Semantic | Rapport / authority manipulation ("you can trust me", "I am your advisor") |
| **SEC-23** | `PiiLeakageDetector` | Rule-based | PII: SSN, credit card, IBAN, BSN, UK NINO, passport, DE tax ID, email + name, phone, DOB |
| **SEC-24** | `AdversarialUnicodeDetector` | Rule-based | Zero-width spaces, homoglyphs, invisible characters used to smuggle hidden instructions |
| **SEC-25** | `CodeInjectionDetector` | Rule-based | SQL injection, shell metacharacters, path traversal in LLM-generated code |
| **SEC-26** | `PromptTemplateLeakageDetector` | Rule-based | Prompt scaffolding markers — `{{variable}}`, `<SYSTEM>`, `[INST]` |
| **SEC-27** | `LanguageSwitchAttackDetector` | Rule-based | Abrupt script / language switch mid-response — injection vector via non-Latin text |
| **SEC-28** | `RefusalBypassDetector` | Rule-based | Model complied with a request it should have refused (caller-supplied forbidden patterns) |
| **SEC-29** | `OutputSchemaDetector` | Rule-based | Response doesn't deserialize as the caller-supplied `ExpectedResponseType` (OWASP LLM05) |
| **SEC-30** | `ShorthandEmergenceDetector` | Semantic | Unknown all-caps tokens that may signal emergent covert language |
| **SEC-31** | `VectorRetrievalPoisoningDetector` | Semantic | Malicious instructions embedded in RAG-retrieved document chunks (OWASP LLM08) |

## Severity ranges

The severity each detector emits depends on what fires:

- **Rule-based detectors** typically pin to one or two severities per pattern class. `PiiLeakageDetector` for example emits `Critical` for credit cards / SSNs, `High` for IBANs, `Medium` for emails+name, `Low` for phone numbers.
- **Semantic detectors** emit `High` / `Medium` / `Low` based on cosine similarity against their reference example sets, with thresholds at 0.90 / 0.82 / 0.75 by default. Override by subclassing and setting `HighThreshold` / `MediumThreshold` / `LowThreshold` overrides.
- **LLM-escalation detectors** start with a rule-based hit and ask a second-pass LLM classifier to confirm or downgrade the severity.

## Tuning specific detectors

A few detectors expose configuration knobs beyond the universal Floor/Cap:

- **`SEC-23 PiiLeakage`** — `IncludePhoneNumbers` / `IncludeDateOfBirth` etc. (planned; today the detector emits all PII patterns it knows about; clamp via `Configure<T>(c => c.SeverityCap = Severity.Low)` to suppress noisy classes).
- **`SEC-19 ToolCallFrequency`** — threshold for "excessive" calls (default 10 per session). Subclass to override.
- **`SEC-29 OutputSchema`** — the expected type comes from the request via `OutputSchemaContext.ExpectedResponseType`; not a startup config.

For everything else, the universal pattern is:

```csharp
opts.Configure<JailbreakDetector>(c =>
{
    c.Enabled = true;                       // already the default
    c.SeverityFloor = Severity.High;        // promote any firing to High+
    c.SeverityCap   = Severity.Critical;    // pass-through Critical unchanged
});
```

## OWASP LLM Top 10 mapping

| OWASP LLM | Detectors |
|---|---|
| **LLM01** Prompt Injection | SEC-01, SEC-09, SEC-31, SEC-26 |
| **LLM02** Insecure Output Handling | SEC-25, SEC-29 |
| **LLM03** Training Data Poisoning | (out of scope — detect at training time, not at inference) |
| **LLM04** Model DoS | OPS-11 (UnboundedConsumption), SEC-19 (ToolCallFrequency) |
| **LLM05** Supply Chain | SEC-17 |
| **LLM06** Sensitive Information Disclosure | SEC-02, SEC-20, SEC-23, SEC-14 |
| **LLM07** Insecure Plugin Design | SEC-03, SEC-18 |
| **LLM08** Excessive Agency | SEC-21 |
| **LLM09** Overreliance | HAL-04 (SourceGrounding), HAL-05 (ConfidenceDecay) |
| **LLM10** Model Theft | (out of scope — needs upstream rate-limiting + auth) |
