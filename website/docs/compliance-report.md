---
sidebar_position: 4
title: Compliance report
---

# Compliance report

`sentinel report` turns the audit file into a report an auditor, privacy officer or regulator can read. It shows that the safeguards ran, not only that they were configured, with totals grouped by [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) article.

The report is evidence to support an assessment, not a compliance verdict. Every format starts with this disclaimer:

> This report summarises what AI.Sentinel recorded in its audit log. It is evidence to support an EU AI Act assessment, not a statement of compliance.

## Usage

The command ships in the `AI.Sentinel.Cli` tool, next to `sentinel dashboard`:

```
dotnet tool install -g AI.Sentinel.Cli
sentinel report [--db <path>] [--from <date>] [--to <date>] [--format md|html|json] [--output <file>]
```

| Option | Default | Meaning |
|---|---|---|
| `--db` | The file the hooks and the MCP proxy write | The audit SQLite file to read. An in-process app passes the `DatabasePath` it gave `AI.Sentinel.Sqlite`. |
| `--from` | 30 days before `--to` | Start of the period. |
| `--to` | Now | End of the period, inclusive. |
| `--format` | `md` | `md` for Markdown, `html` for one self-contained page, `json` for other tools. |
| `--output` | Standard output | File to write the report to. The report is written to a temporary file and then moved over the target, and the audit file and its `-wal` and `-shm` files are refused. |

`--from` and `--to` take an ISO date such as `2026-10-01` or an ISO 8601 timestamp such as `2026-10-01T09:30:00+02:00`. A date is a UTC day: `--from 2026-10-01` starts at 00:00 UTC that day, and `--to 2026-10-31` runs to the end of 31 October UTC. A timestamp without an offset is read as UTC.

```
sentinel report --from 2026-10-01 --to 2026-10-31 --format html --output october.html
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The report was written and the hash chain is intact. |
| `1` | Usage error, such as an invalid date or `--from` after `--to`, or the audit file is missing, unreadable or not an AI.Sentinel audit file. |
| `2` | The hash chain is broken. The report is still written and shows where the chain breaks. |

A scheduled job can alert on a non-zero code.

### Read-only

The command opens the audit file read-only. It never creates a missing file, never upgrades an older schema, and never appends, trims or deletes entries: the audit file itself is never changed. SQLite may create its `-wal` and `-shm` coordination files next to it. Where it cannot, for example in a read-only directory or on read-only media, the command opens the file as immutable instead and creates nothing. A file written by an older AI.Sentinel version must first be opened once by a current writer, such as a hook or your app, which upgrades its schema.

## Sections

| Section | What it shows |
|---|---|
| Header | Period, generation time, the audit file and the disclaimer. |
| Art. 12 Record keeping | Whether the hash chain is intact, the entries verified, the first broken entry, whether the head was trimmed, and the entries in the period per source. In-process applications show as `in-process`. |
| Art. 14 Human oversight | Authorization denials, tool calls held for [approval](./approvals/overview), and approval requests per outcome: approved, denied, expired or timed out. A hold is written as an `AUTHZ-DENY` entry with the `approval_required` code and is counted as a hold, not a denial; a call held three times counts three holds. Each request counts once per outcome. |
| Art. 10 Data minimisation and GDPR | [Redactions](./redaction) per entity type, and detections that wanted redaction but could not redact. Those detections are also counted under Art. 15, or Art. 5 for a `CMP-` detector. |
| Art. 50 Transparency | Conversations with a [disclosure](./transparency) entry. A disclosure without a session key counts as its own conversation. |
| Art. 5 Prohibited practices | Detections of the `CMP-` detectors, per detector and severity. |
| Art. 15 Accuracy and robustness | All other detections per detector and severity, and the five detectors with the most detections. |

A section with nothing to show says so, for example "No entries in this period." or "No approval decisions recorded in this period.", and adds a note on what would populate it. The JSON carries the same note in each section's `note` property, `null` when the section has data.

| Section | Note when empty |
|---|---|
| Art. 12 | Entries are written by `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp`, and by an in-process application that registers `AI.Sentinel.Sqlite` with this file. An application on the default in-memory audit store writes nothing here, so check that `--db` names the file they write. |
| Art. 14 | Authorization denials need a tool-call authorization policy that refuses a call, and approval holds and decisions need an approval policy that gates a tool. The hook tools and the MCP proxy write them to the audit file by default; an in-process application does only when it registers `AI.Sentinel.Sqlite` with that file. Shown only when there are no denials, holds or decisions at all. |
| Art. 10 | Redaction entries come from the in-process chat client pipeline. The hook tools and the MCP proxy do not redact yet ([#364](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/364)); a detection there that wanted redaction is counted as could not be redacted. |
| Art. 50 | [Transparency](./transparency) is opt-in through `SentinelOptions.Transparency` and applies to the in-process chat client only. The hook tools and the MCP proxy never write disclosures. |
| Art. 5 | The Art. 5 detectors are opt-in: no detections means nothing was detected while they were enabled, not that no prohibited-practice request occurred. |
| Art. 15 | A detection is recorded each time a detector fires on a scanned prompt, response or tool call. The semantic detectors only run with an embedding generator configured; without one only the rule-based detectors can fire. |

### Chain verification

The hash chain is global, so the command verifies it over the whole audit file, oldest entry first, not only the period. [Retention](./core-concepts/audit-store#retention-strategies) legitimately removes the oldest entries; when the head of the file was trimmed, the chain is verified from the oldest retained entry and the report says the head was trimmed.

### Totals only

The report holds counts and codes only. It never contains a detection summary, a message, a redacted value, a session id or a caller id. Per-session drill-down stays in the [dashboard](./getting-started/dashboard).

## Formats

- **Markdown** is the default and reads well in a pull request, a wiki or a ticket.
- **HTML** is one self-contained file in a light theme, with inline CSS, no script and no external reference, so it can be archived or attached as is.
- **JSON** uses camelCase property names and carries `"schema": 1`, so a tool can check the shape before it reads the rest. Severities are names such as `"High"`.

```json
{
  "schema": 1,
  "from": "2026-10-01T00:00:00+00:00",
  "to": "2026-10-31T23:59:59.9999999+00:00",
  "generatedAt": "2026-11-01T08:00:00+00:00",
  "auditFilePath": "/home/me/.local/share/ai-sentinel/audit.db",
  "disclaimer": "This report summarises what AI.Sentinel recorded in its audit log. ...",
  "art12": { "chainIntact": true, "entriesChecked": 1520, "firstBrokenEntryId": null, "headTrimmed": false, "chainNote": "...", "entriesInPeriod": 412, "entriesBySource": { "claude-code": 300, "mcp": 112 }, "note": null },
  "art14": { "authorizationDenials": 3, "approvalHolds": 7, "approvalRequestsByOutcome": { "APPROVED": 5, "DENIED": 1 }, "note": null },
  "art10": { "redactionsByType": { "EMAIL": 12, "IBAN": 2 }, "fallbackEntries": 0, "note": null },
  "art50": { "disclosedSessions": 0, "note": "Transparency is opt-in through SentinelOptions.Transparency ..." },
  "art5": { "anyDetections": false, "note": "No Art. 5 detections were recorded. ...", "detections": [] },
  "art15": { "detections": [ { "detectorId": "SEC-01", "severity": "High", "count": 4 } ], "topDetectors": [ { "detectorId": "SEC-01", "count": 4 } ], "note": null }
}
```

## Sample report

A Markdown report for a month in which the hooks, the MCP proxy and an in-process application wrote to the same audit file:

````markdown
# AI.Sentinel compliance report

> This report summarises what AI.Sentinel recorded in its audit log. It is evidence to support an EU AI Act assessment, not a statement of compliance.

| | |
|---|---|
| Period | 2026-10-01 00:00:00 UTC to 2026-10-31 23:59:59 UTC |
| Generated | 2026-11-01 08:00:00 UTC |
| Audit file | `/home/me/.local/share/ai-sentinel/audit.db` |

## Art. 12 Record keeping

- Hash chain: intact, 15 entries verified.
- Head trimmed: no
- Entries in period: 15

The hash chain is verified over the whole audit file, oldest entry first, not only the period. When retention has trimmed the head of the file, the chain is verified from the oldest retained entry.

### Entries by source

| Source | Entries |
|---|---:|
| claude-code | 7 |
| in-process | 4 |
| mcp | 4 |

## Art. 14 Human oversight

- Authorization denials: 1
- Tool calls held for approval: 3

### Approval decisions

| Outcome | Requests |
|---|---:|
| APPROVED | 1 |
| DENIED | 1 |

## Art. 10 Data minimisation and GDPR

### Redactions by type

| Entity type | Redacted |
|---|---:|
| EMAIL | 12 |
| IBAN | 2 |

Detections that could not be redacted: 0.

## Art. 50 Transparency

No disclosures recorded in this period.

Transparency is opt-in through SentinelOptions.Transparency and applies to the in-process chat client only. The hook tools and the MCP proxy never write disclosures.

## Art. 5 Prohibited practices

No Art. 5 detections were recorded. The Art. 5 detectors are opt-in; this means nothing was detected while they were enabled, not that no prohibited-practice request occurred.

## Art. 15 Accuracy and robustness

| Detector | Severity | Detections |
|---|---|---:|
| OPS-02 | Low | 1 |
| SEC-01 | High | 4 |
| SEC-05 | Medium | 2 |

### Top detectors

| Detector | Detections |
|---|---:|
| SEC-01 | 4 |
| SEC-05 | 2 |
| OPS-02 | 1 |
````
