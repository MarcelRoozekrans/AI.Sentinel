using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PiiLeakageDetector : ILlmEscalatingDetector, IRedactingDetector
{
    private static readonly DetectorId _id = new("SEC-23");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    // --- Critical ---

    [GeneratedRegex(
        @"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex CreditCardPattern();

    // --- High ---

    [GeneratedRegex(
        @"\b\d{3}-\d{2}-\d{4}\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SsnPattern();

    [GeneratedRegex(
        @"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex IbanPattern();

    // The keyword-prefixed patterns allow a quote after the keyword and before the value, so the JSON
    // `"BSN": "123456789"` matches as `BSN: 123456789` does; a JSON value is judged with its key.
    // A multi-word keyword also matches written as an identifier, as JSON keys usually are:
    // `date_of_birth`, `date-of-birth`, `dateOfBirth`, `tax_id`, `taxId`.
    // Whitespace after the keyword is taken once, before the optional separator, and again only
    // after a separator: two adjacent runs that could split one stretch of whitespace between
    // them made a keyword followed by a long run of spaces quadratic.
    [GeneratedRegex(
        @"(?:BSN|burgerservicenummer)[""']?\s*(?:[:=]\s*)?[""']?(?<value>\d{9})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BsnPattern();

    [GeneratedRegex(
        @"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex UkNinoPattern();

    [GeneratedRegex(
        @"passport[""']?\s*(?:[:=]\s*)?[""']?(?<value>[A-Z]{1,2}\d{6,9})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PassportPattern();

    [GeneratedRegex(
        @"(?:Steuer(?:\s+|[_-])?ID|tax(?:\s+|[_-])?id)[""']?\s*(?:[:=]\s*)?[""']?(?<value>\d{2}\s?\d{3}\s?\d{5})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DeTaxIdPattern();

    // --- Medium ---

    [GeneratedRegex(
        @"\b[\w.+-]{1,64}@(?:[A-Za-z0-9][\w-]{0,62}\.){1,8}[A-Za-z]{2,}\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareEmailPattern();

    // The last alternative is a Dutch number written without a separator: 0, a non-zero digit, eight more
    // digits, not part of a longer token, so an IBAN or a reference code ending in ten digits stays clean.
    [GeneratedRegex(
        @"(?<!\d)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}\b|\(?\d{1,4}\)?[\s.-]\d{3,4}[\s.-]?\d{4}\b)" +
        @"|(?<!\w)0[1-9]\d{8}(?!\w)",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PhonePattern();

    // English and Dutch keywords, an optional "on" or "op" before the value, and three date shapes:
    // numeric, day month-name year, and the English month-name day year. A month name is written out
    // or abbreviated, with an optional dot. A written date needs a four-digit year.
    [GeneratedRegex(
        @"(?:born|DOB|date(?:\s+|[_-])?of(?:\s+|[_-])?birth|geboren|geboorte(?:\s+|[_-])?datum|geb\.(?:\s?datum)?)" +
        @"[""']?\s*(?:[:=]\s*)?[""']?(?:o[np]\s+)?" +
        @"(?<value>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{1,2}\s+" + Month + @"\.?\s+\d{4}|" + Month + @"\.?\s+\d{1,2},?\s+\d{4})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DobPattern();

    private const string Month =
        @"(?:jan(?:uar[iy])?|feb(?:ruar[iy])?|maart|march|mrt|mar|apr(?:il)?|mei|may|jun[ie]?|jul[iy]?" +
        @"|aug(?:ust(?:us)?)?|sep(?:t(?:ember)?)?|o[kc]t(?:ober)?|nov(?:ember)?|dec(?:ember)?)";

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var severity = Severity.None;
        var names = new List<string>();

        // Every pattern is tested, in severity order, so the reason names each type found.
        Probe(CreditCardPattern(), Severity.Critical, "credit card number");
        Probe(SsnPattern(), Severity.High, "SSN");
        Probe(IbanPattern(), Severity.High, "IBAN");
        Probe(BsnPattern(), Severity.High, "BSN");
        Probe(UkNinoPattern(), Severity.High, "UK National Insurance number");
        Probe(PassportPattern(), Severity.High, "passport number");
        Probe(DeTaxIdPattern(), Severity.High, "German tax ID");
        Probe(BareEmailPattern(), Severity.Medium, "email address");
        Probe(PhonePattern(), Severity.Medium, "phone number");
        Probe(DobPattern(), Severity.Medium, "date of birth");

        if (names.Count == 0)
            return ValueTask.FromResult(_clean);

        var list = names.Count == 1
            ? names[0]
            : string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1];
        return Hit(severity, char.ToUpperInvariant(list[0]) + list[1..] + " detected");

        void Probe(Regex pattern, Severity patternSeverity, string name)
        {
            if (!pattern.IsMatch(text))
                return;
            names.Add(name);
            if (patternSeverity > severity)
                severity = patternSeverity;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<RedactionSpan> FindSpans(string text)
    {
        var spans = new List<RedactionSpan>();
        RedactionSpanCollector.Collect(CreditCardPattern(), "CREDIT_CARD", text, spans, Severity.Critical);
        RedactionSpanCollector.Collect(SsnPattern(), "SSN", text, spans, Severity.High);
        RedactionSpanCollector.Collect(IbanPattern(), "IBAN", text, spans, Severity.High);
        RedactionSpanCollector.Collect(BsnPattern(), "BSN", text, spans, Severity.High);
        RedactionSpanCollector.Collect(UkNinoPattern(), "NINO", text, spans, Severity.High);
        RedactionSpanCollector.Collect(PassportPattern(), "PASSPORT", text, spans, Severity.High);
        RedactionSpanCollector.Collect(DeTaxIdPattern(), "TAX_ID", text, spans, Severity.High);
        RedactionSpanCollector.Collect(BareEmailPattern(), "EMAIL", text, spans, Severity.Medium);
        RedactionSpanCollector.Collect(PhonePattern(), "PHONE", text, spans, Severity.Medium);
        RedactionSpanCollector.Collect(DobPattern(), "DATE_OF_BIRTH", text, spans, Severity.Medium);
        return RedactionSpanCollector.Normalize(spans);
    }

    private static ValueTask<DetectionResult> Hit(Severity severity, string reason)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, reason));
}
