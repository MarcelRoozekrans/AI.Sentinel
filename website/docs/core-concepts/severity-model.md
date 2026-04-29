---
sidebar_position: 5
title: Severity model
---

# Severity model

Five severity levels, ordered from least to most concerning:

| Severity   | Use when                                                                |
|------------|-------------------------------------------------------------------------|
| `Critical` | Active exploitation, data exfiltration, credential leak                 |
| `High`     | Likely threat with high confidence (e.g., direct injection phrase match)|
| `Medium`   | Suspicious pattern with moderate confidence                             |
| `Low`      | Anomaly worth flagging but probably benign                              |
| `None`     | No threat — `DetectionResult.IsClean == true`                           |

The pipeline aggregates per-detector severities into a **Threat Risk Score** (0–100) that drives intervention decisions:

| Severity | Score |
|---|---|
| Critical | 100 |
| High | 70 |
| Medium | 40 |
| Low | 15 |
| None | 0 |

> Full severity model guide — risk score aggregation, custom severity mappers, severity-floor/cap clamping — coming soon.
