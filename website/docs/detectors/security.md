---
sidebar_position: 2
title: Security detectors
---

# Security detectors

The 31 security detectors look for prompt injection, jailbreaks, credential / PII leakage, covert channels, and indirect injection patterns.

Highlights:

- **`SEC-01` PromptInjection** — override/injection phrase patterns
- **`SEC-02` CredentialExposure** — API keys, tokens, private keys in output
- **`SEC-05` Jailbreak** — DAN-style jailbreak attempts
- **`SEC-09` IndirectInjection** — injection via retrieved documents or tool results
- **`SEC-23` PiiLeakage** — SSN, credit card, IBAN, BSN, UK NINO, passport, DE tax ID, email+name, phone, DOB
- **`SEC-24` AdversarialUnicode** — zero-width spaces, homoglyphs, invisible characters

> Full reference for all 31 security detectors — coming soon. See the [README](https://github.com/ZeroAlloc-Net/AI.Sentinel#detectors-55) for the current detector table.
