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

    [GeneratedRegex(
        @"(?<!\d)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}\b|\(?\d{1,4}\)?[\s.-]\d{3,4}[\s.-]?\d{4}\b)",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PhonePattern();

    [GeneratedRegex(
        @"(?:born|DOB|date(?:\s+|[_-])?of(?:\s+|[_-])?birth)[""']?\s*(?:[:=]\s*)?[""']?(?<value>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DobPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;

        // Critical
        if (CreditCardPattern().IsMatch(text))
            return Hit(Severity.Critical, "Credit card number detected");

        // High
        if (SsnPattern().IsMatch(text))
            return Hit(Severity.High, "SSN detected");
        if (IbanPattern().IsMatch(text))
            return Hit(Severity.High, "IBAN detected");
        if (BsnPattern().IsMatch(text))
            return Hit(Severity.High, "BSN detected");
        if (UkNinoPattern().IsMatch(text))
            return Hit(Severity.High, "UK National Insurance number detected");
        if (PassportPattern().IsMatch(text))
            return Hit(Severity.High, "Passport number detected");
        if (DeTaxIdPattern().IsMatch(text))
            return Hit(Severity.High, "German tax ID detected");

        // Medium
        if (BareEmailPattern().IsMatch(text))
            return Hit(Severity.Medium, "Email address detected");
        if (PhonePattern().IsMatch(text))
            return Hit(Severity.Medium, "Phone number detected");
        if (DobPattern().IsMatch(text))
            return Hit(Severity.Medium, "Date of birth detected");

        return ValueTask.FromResult(_clean);
    }

    /// <inheritdoc />
    public IReadOnlyList<RedactionSpan> FindSpans(string text)
    {
        var spans = new List<RedactionSpan>();
        RedactionSpanCollector.Collect(CreditCardPattern(), "CREDIT_CARD", text, spans);
        RedactionSpanCollector.Collect(SsnPattern(), "SSN", text, spans);
        RedactionSpanCollector.Collect(IbanPattern(), "IBAN", text, spans);
        RedactionSpanCollector.Collect(BsnPattern(), "BSN", text, spans);
        RedactionSpanCollector.Collect(UkNinoPattern(), "NINO", text, spans);
        RedactionSpanCollector.Collect(PassportPattern(), "PASSPORT", text, spans);
        RedactionSpanCollector.Collect(DeTaxIdPattern(), "TAX_ID", text, spans);
        RedactionSpanCollector.Collect(BareEmailPattern(), "EMAIL", text, spans);
        RedactionSpanCollector.Collect(PhonePattern(), "PHONE", text, spans);
        RedactionSpanCollector.Collect(DobPattern(), "DATE_OF_BIRTH", text, spans);
        return RedactionSpanCollector.Normalize(spans);
    }

    private static ValueTask<DetectionResult> Hit(Severity severity, string reason)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, reason));
}
