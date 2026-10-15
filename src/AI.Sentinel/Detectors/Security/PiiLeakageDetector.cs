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

    [GeneratedRegex(
        @"(?:BSN|burgerservicenummer)\s*[:=]?\s*(?<value>\d{9})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BsnPattern();

    [GeneratedRegex(
        @"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex UkNinoPattern();

    [GeneratedRegex(
        @"passport\s*[:=]?\s*(?<value>[A-Z]{1,2}\d{6,9})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PassportPattern();

    [GeneratedRegex(
        @"(?:Steuer-?ID|tax\s+id)\s*[:=]?\s*(?<value>\d{2}\s?\d{3}\s?\d{5})\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DeTaxIdPattern();

    // --- Medium ---

    [GeneratedRegex(
        @"\b[\w.+-]+@(?:[\w-]+\.)+\w{2,}\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareEmailPattern();

    [GeneratedRegex(
        @"(?<!\d)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}\b|\(?\d{1,4}\)?[\s.-]\d{3,4}[\s.-]?\d{4}\b)",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PhonePattern();

    [GeneratedRegex(
        @"(?:born|DOB|date\s+of\s+birth)\s*[:=]?\s*(?<value>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\b",
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
        Collect(CreditCardPattern(), "CREDIT_CARD", text, spans);
        Collect(SsnPattern(), "SSN", text, spans);
        Collect(IbanPattern(), "IBAN", text, spans);
        Collect(BsnPattern(), "BSN", text, spans);
        Collect(UkNinoPattern(), "NINO", text, spans);
        Collect(PassportPattern(), "PASSPORT", text, spans);
        Collect(DeTaxIdPattern(), "TAX_ID", text, spans);
        Collect(BareEmailPattern(), "EMAIL", text, spans);
        Collect(PhonePattern(), "PHONE", text, spans);
        Collect(DobPattern(), "DATE_OF_BIRTH", text, spans);
        return DropContained(spans);
    }

    // A card number also looks like a phone number; keep only the outermost span.
    private static List<RedactionSpan> DropContained(List<RedactionSpan> spans)
    {
        var result = new List<RedactionSpan>(spans.Count);
        for (var i = 0; i < spans.Count; i++)
        {
            var inner = spans[i];
            var contained = false;
            for (var j = 0; j < spans.Count && !contained; j++)
            {
                var outer = spans[j];
                contained = j != i
                    && outer.Start <= inner.Start
                    && outer.Start + outer.Length >= inner.Start + inner.Length
                    && (outer.Length > inner.Length || j < i);
            }
            if (!contained) result.Add(inner);
        }
        return result;
    }

    // Keyword-prefixed patterns name their value group, so the span excludes the keyword.
    private static void Collect(Regex pattern, string entityType, string text, List<RedactionSpan> spans)
    {
        foreach (Match m in pattern.Matches(text))
        {
            var g = m.Groups["value"];
            var target = g.Success ? g : m;
            spans.Add(new RedactionSpan(target.Index, target.Length, entityType));
        }
    }

    private static ValueTask<DetectionResult> Hit(Severity severity, string reason)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, reason));
}
