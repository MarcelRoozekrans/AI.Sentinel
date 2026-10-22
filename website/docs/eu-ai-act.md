---
title: EU AI Act
---

# EU AI Act

AI.Sentinel provides runtime building blocks for several technical obligations of [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj), the AI Act. It does not make a system compliant on its own. Classification, risk management, technical documentation, conformity assessment and registration stay with the provider and deployer, and most of these articles bind high-risk systems specifically.

This page lists, article by article, what AI.Sentinel provides, what is active by default and where it stops. **Active by default** means what a stock `AddAISentinel()` install does with no further configuration.

[`sentinel report`](./compliance-report) turns the audit file into a report with totals for these articles, as Markdown, HTML or JSON. Like everything on this page, it is evidence, not a verdict. Every report starts with this disclaimer:

> This report summarises what AI.Sentinel recorded in its audit log. It is evidence to support an EU AI Act assessment, not a statement of compliance.

## Summary

| Article | Requirement | Active by default |
|---|---|---|
| [Art. 5](#art-5-prohibited-practices) | Prohibited practices | ❌ none: the four detectors are opt-in |
| [Art. 10](#art-10-data-and-data-governance) | Data and data governance | ⚠️ partial: PII and credential redaction, with limits in the hook CLIs and the MCP proxy |
| [Art. 12](#art-12-record-keeping) | Record-keeping | ⚠️ partial: hash-chained, durable in the CLIs, in memory in an app |
| [Art. 14](#art-14-human-oversight) | Human oversight | ❌ none: every tool call is allowed until policies or approvals are configured |
| [Art. 15](#art-15-accuracy-robustness-and-cybersecurity) | Accuracy, robustness and cybersecurity | ⚠️ partial: the rule-based detectors |
| [Art. 50](#art-50-transparency) | Transparency obligations | ❌ none: opt-in |

## Art. 5 Prohibited practices

**What AI.Sentinel provides.** Four [compliance detectors](./detectors/compliance) flag requests to use the model for social scoring (`CMP-01`), emotion recognition at work or in education (`CMP-02`), biometric categorisation of sensitive traits (`CMP-03`) and predicting crime from profiling (`CMP-04`). They scan both the request and the reply.

**Active by default.** None. They stay off until `opts.EnableComplianceDetectors()`, or `SENTINEL_HOOK_COMPLIANCE=on` for the hook CLIs and `SENTINEL_MCP_COMPLIANCE=on` for the MCP proxy. All four are semantic and need an embedding generator.

Once enabled, a strong match in an `AddAISentinel()` app is `High`, so the default action is `Alert`: it is logged and alerted, not blocked. A weaker match is `Medium` and is logged. `opts.Configure<T>(c => c.Action = SentinelAction.Quarantine)` blocks it. The hook CLIs and the MCP proxy give these four detectors the `Alert` action at both `High` and `Medium`, so they warn rather than block.

**Limits.**

- Subliminal manipulation, exploiting vulnerabilities, untargeted facial-image scraping and real-time remote biometric identification are not covered.
- The thresholds are tuned on `all-MiniLM-L6-v2` and are model-dependent; set them per detector for another model.
- They flag attempts to use the model for these practices. They do not establish that a system is or is not prohibited.

## Art. 10 Data and data governance

**What AI.Sentinel provides.** `PiiLeakageDetector` and `CredentialExposureDetector` find personal data and secrets in prompts and responses and, by default, [redact](./redaction) them, so the model sees a placeholder and never the value. `DataExfiltrationDetector` and `InformationFlowDetector` cover encoded and cross-context leakage.

**Active by default.** Partial: the two rule-based detectors, with redaction on (`RedactByDefault = true`). The other two are semantic and need an embedding generator.

**Limits.**

- The hook CLIs and the MCP proxy redact tool results, and the MCP proxy also prompts and resources, but they cannot redact everything ([per surface](./redaction#per-surface)). Tool-call arguments are not redacted, and neither is the prompt on Claude Code `UserPromptSubmit` or Copilot `userPromptSubmitted`. Prompt redaction through Copilot `userPromptTransformed` is experimental. Where they cannot redact, a PII or credential finding falls back to the action of its severity.
- The response scan cannot redact either, since redaction only applies to what goes to the model.
- These detectors keep values away from the model. They do not make a system's training, validation and test data compliant, which is what Art. 10 is mainly about.

The same mechanism supports GDPR data minimisation (Art. 5(1)(c)) and data protection by design (Art. 25).

## Art. 12 Record-keeping

**What AI.Sentinel provides.** Every detection, authorization denial and approval decision is written to the [audit store](./core-concepts/audit-store) and linked into a SHA-256 hash chain, so an edited, inserted or deleted entry is detectable with `AuditHashChain.VerifyAsync`. `AI.Sentinel.Sqlite` persists it with `RetentionPeriod`. [Audit forwarders](./audit-forwarders/overview) mirror it, chain hashes included, to NDJSON, Azure Sentinel or OpenTelemetry.

**Active by default.** Partial. The hook CLIs (`sentinel-hook`, `sentinel-copilot-hook`) and the MCP proxy (`sentinel-mcp`) record findings, denials and approval holds durably to a local SQLite file, with a `Source` on each entry. An in-process app defaults to the in-memory ring buffer, capped at `opts.AuditCapacity` entries and lost on restart, until it registers `AI.Sentinel.Sqlite`.

**Limits.** The hook CLIs and the MCP proxy do not record allowed calls. The chain detects tampering; it does not prevent it.

## Art. 14 Human oversight

**What AI.Sentinel provides.** [Tool-call authorization](./authorization/overview) and the [approval workflow](./approvals/overview): `RequireApproval` holds a tool call until a person approves it in the dashboard or in Entra PIM (`AI.Sentinel.Approvals.Sqlite`, `AI.Sentinel.Approvals.EntraPim`). The [dashboard](./getting-started/dashboard) shows detections live. Denials, approval holds and approval decisions are recorded in the audit log and reported by `sentinel report`.

**Active by default.** None. Every tool call is allowed until policies or approvals are configured.

**Limits.** AI.Sentinel can hold a tool call for a person; designing the oversight measures and training the people who exercise them stays with you. With Entra PIM the decision is made in PIM, so AI.Sentinel records only what it observes; see the [audit trail](./approvals/overview#audit-trail).

## Art. 15 Accuracy, robustness and cybersecurity

**What AI.Sentinel provides.** The 56 [Security](./detectors/security), [Hallucination](./detectors/hallucination) and [Operational](./detectors/operational) detectors, covering prompt injection, jailbreaks, data leakage, hallucinated citations and runaway agents, and optional prompt hardening with `SystemPrefix`.

**Active by default.** Partial: 15 rule-based detectors. The 39 semantic detectors need an embedding generator, and `SystemPrefix` is opt-in.

**Limits.** The detectors judge what passes through the pipeline at run time. They do not measure a model's accuracy, and they say nothing about robustness that has to be designed into the system itself.

## Art. 50 Transparency

**What AI.Sentinel provides.** Opt-in [transparency](./transparency). `opts.Transparency.Enabled` marks each reply in `ChatResponse.AdditionalProperties` with the `TransparencyKeys`: `ai.generated`, `ai.model_id`, `ai.generated_at`, and `ai.pipeline` for a reply from a named pipeline. It adds a configurable notice once per conversation or on every reply, or, with `NoticeMode = Never`, sets the mark only. Each first disclosure of a conversation is written to the audit store as a `DISCLOSED` entry.

**Active by default.** None. Transparency is off until `opts.Transparency.Enabled = true`.

**Limits.** It covers the in-process chat client. The hook CLIs and the MCP proxy do not mark replies or add a notice. Whether and how Art. 50 applies to your system, and whether this is enough, stays with you.

## Timeline

The Art. 5 prohibitions have applied since 2 February 2025. [Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj), the Digital Omnibus on AI, in force since 27 July 2026, moved the obligations for Annex III high-risk systems from 2 August 2026 to **2 December 2027**, and for high-risk systems under Annex I to 2 August 2028. Check the regulation itself for the dates that apply to your system.
