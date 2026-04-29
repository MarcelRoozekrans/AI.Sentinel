---
sidebar_position: 1
title: Overview
---

# Detector overview

AI.Sentinel ships with **51 built-in detectors** across three categories:

| Category | Count | Purpose |
|---|---|---|
| **Security** | 31 | Prompt injection, jailbreaks, PII / credential leakage, covert channels, indirect injection |
| **Hallucination** | 10 | Phantom citations, fabricated authorities, contradictions, agreement bias |
| **Operational** | 10 | Repetition loops, blank responses, truncated output, language switches, placeholder text |

Detectors run in three modes:

- **Rule-based** — fast regex or heuristic, always active, sub-microsecond per call
- **Semantic** — uses embedding cosine similarity. Language-agnostic. Active only with `opts.EmbeddingGenerator` configured
- **LLM escalation** — fires a second-pass LLM classifier (active only with `opts.EscalationClient`)

> Full per-detector reference for all 51 detectors — IDs, modes, severity ranges, configurable thresholds — coming soon. See [Security](./security), [Hallucination](./hallucination), [Operational](./operational).
