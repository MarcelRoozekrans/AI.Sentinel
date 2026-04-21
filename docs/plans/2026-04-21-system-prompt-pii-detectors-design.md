# SystemPromptLeakageDetector + PiiLeakageDetector Design

**Goal:** Add two rule-based security detectors that protect against leaking sensitive information — system prompt internals (OWASP LLM07) and personally identifiable information (PII) across US, EU, and international formats.

**Architecture:** Both detectors follow the existing `IDetector` pattern. `SystemPromptLeakageDetector` uses n-gram string matching against the `ChatRole.System` message. `PiiLeakageDetector` uses multiple named `[GeneratedRegex]` patterns tested sequentially with short-circuit on first match. Zero configuration required.

**Tech Stack:** `[GeneratedRegex]` (compile-time regex), `ZeroAlloc.Inject` (`[Singleton]` for DI registration), xUnit.

---

## SEC-20 `SystemPromptLeakageDetector`

### Behaviour

Extracts the `ChatRole.System` message text from `ctx.Messages`. If none exists, returns clean. Otherwise, generates n-gram windows (sequences of N consecutive words, default N=5) from the system prompt. Scans `ctx.TextContent` for verbatim case-insensitive matches of any window.

### Severity logic

- 1 matching fragment → `Medium` ("Possible system prompt leakage")
- 2+ fragments OR single fragment >= 10 words → `High` ("Significant system prompt leakage")

### Edge cases

- No `ChatRole.System` message → clean (nothing to protect)
- System prompt shorter than N words → use the full text as a single window
- Empty system prompt → clean

### Class design

- Implements `IDetector` (not `ILlmEscalatingDetector` — pure string matching)
- `[Singleton(As = typeof(IDetector), AllowMultiple = true)]`
- ID: `SEC-20`, Category: `Security`

---

## SEC-23 `PiiLeakageDetector`

### Behaviour

Multiple named `[GeneratedRegex]` patterns, tested sequentially against `ctx.TextContent`. Short-circuits on first match. Reason string names the specific PII type (e.g., "IBAN detected", "SSN detected").

### Patterns (10 categories)

| Category | Pattern | Example | Severity |
|---|---|---|---|
| SSN (US) | `\b\d{3}-\d{2}-\d{4}\b` | 123-45-6789 | High |
| BSN (NL) | `\b\d{9}\b` with keyword context (`BSN`, `burgerservicenummer`) | BSN: 123456782 | High |
| UK NINO | `\b[A-Z]{2}\d{6}[A-Z]\b` | AB123456C | High |
| Credit card | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` | 4111-1111-1111-1111 | Critical |
| IBAN | `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}\b` | NL91ABNA0417164300 | High |
| Email + name | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b.*\b[\w.]+@[\w.]+\.\w{2,}\b` | John Smith john@example.com | Medium |
| Phone (intl) | `\b\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b` | +31 6 12345678 | Medium |
| DOB | `\b(?:born\|DOB\|date of birth)[:\s]+\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b` | DOB: 15/03/1990 | Medium |
| Passport | `\b[A-Z]{1,2}\d{6,9}\b` with keyword context (`passport`) | Passport: AB1234567 | High |
| DE Tax ID | `\b\d{2}\s?\d{3}\s?\d{5}\b` with keyword context (`Steuer-ID`, `tax id`) | Steuer-ID: 12 345 67890 | High |

### Design choices

- BSN, passport, and DE tax ID use keyword proximity context to reduce false positives (a bare 9-digit number is too common)
- Email alone is not flagged; email + name combo is `Medium`
- Credit card is `Critical` (PCI-DSS territory)
- Phone is `Medium` — common in legitimate business context

### Class design

- Implements `IDetector` (not `ILlmEscalatingDetector` — pure regex)
- `[Singleton(As = typeof(IDetector), AllowMultiple = true)]`
- ID: `SEC-23`, Category: `Security`

---

## Testing

### `SystemPromptLeakageDetectorTests`

| Test | Verifies |
|---|---|
| `NoSystemMessage_ReturnsClean` | No `ChatRole.System` → clean |
| `CleanResponse_NoLeakage` | Response doesn't echo system prompt → clean |
| `SingleFragment_ReturnsMedium` | One 5-word match → Medium |
| `MultipleFragments_ReturnsHigh` | 2+ matches → High |
| `LongFragment_ReturnsHigh` | Single >= 10-word match → High |
| `ShortSystemPrompt_UsesFullText` | System prompt < 5 words → uses entire text |

### `PiiLeakageDetectorTests`

| Test | Verifies |
|---|---|
| `CleanText_ReturnsClean` | No PII → clean |
| `Ssn_Detected` | `123-45-6789` → High |
| `CreditCard_Detected` | `4111-1111-1111-1111` → Critical |
| `Iban_Detected` | `NL91ABNA0417164300` → High |
| `Bsn_WithContext_Detected` | `BSN: 123456782` → High |
| `UkNino_Detected` | `AB123456C` → High |
| `EmailWithName_Detected` | `John Smith john@example.com` → Medium |
| `Phone_Detected` | `+31 6 12345678` → Medium |
| `Dob_Detected` | `DOB: 15/03/1990` → Medium |
| `Passport_WithContext_Detected` | `passport: AB1234567` → High |
| `DeTaxId_WithContext_Detected` | `Steuer-ID: 12 345 67890` → High |
| `BareNineDigits_WithoutContext_Clean` | `123456789` alone → clean |

---

## Files changed

| Action | File |
|---|---|
| New | `src/AI.Sentinel/Detectors/Security/SystemPromptLeakageDetector.cs` |
| New | `src/AI.Sentinel/Detectors/Security/PiiLeakageDetector.cs` |
| New | `tests/AI.Sentinel.Tests/Detectors/Security/SystemPromptLeakageDetectorTests.cs` |
| New | `tests/AI.Sentinel.Tests/Detectors/Security/PiiLeakageDetectorTests.cs` |
| Modify | `README.md` — add two detectors to table, bump count 30 → 32 |
| Modify | `docs/BACKLOG.md` — remove SEC-20 and SEC-23 |
