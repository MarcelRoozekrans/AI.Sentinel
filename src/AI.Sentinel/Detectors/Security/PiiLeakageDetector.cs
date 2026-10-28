using System.Numerics;
using System.Text;
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

    // Every PII type in severity order: the pattern, the redaction entity type, the name in the reason and the
    // severity of a hit. AnalyzeAsync and FindSpans both read it, so a type's severity is set in one place.
    private static readonly (Func<Regex> Pattern, string EntityType, string Name, Severity Severity)[] _types =
    [
        (CreditCardPattern, "CREDIT_CARD", "credit card number", Severity.Critical),
        (SsnPattern, "SSN", "SSN", Severity.High),
        (IbanPattern, "IBAN", "IBAN", Severity.High),
        (BsnPattern, "BSN", "BSN", Severity.High),
        (UkNinoPattern, "NINO", "UK National Insurance number", Severity.High),
        (PassportPattern, "PASSPORT", "passport number", Severity.High),
        (DeTaxIdPattern, "TAX_ID", "German tax ID", Severity.High),
        (BareEmailPattern, "EMAIL", "email address", Severity.Medium),
        (PhonePattern, "PHONE", "phone number", Severity.Medium),
        (DobPattern, "DATE_OF_BIRTH", "date of birth", Severity.Medium),
    ];

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var severity = Severity.None;
        var found = 0;

        // Every pattern is tested, in severity order, so the reason names each type found.
        for (var i = 0; i < _types.Length; i++)
        {
            if (!_types[i].Pattern().IsMatch(text))
                continue;
            found |= 1 << i;
            if (_types[i].Severity > severity)
                severity = _types[i].Severity;
        }

        return found == 0 ? ValueTask.FromResult(_clean) : Hit(severity, Reason(found));
    }

    /// <summary>"Phone number and date of birth detected": the names of the types in <paramref name="found"/>,
    /// a bit per <see cref="_types"/> entry, in table order.</summary>
    private static string Reason(int found)
    {
        var count = BitOperations.PopCount((uint)found);
        var reason = new StringBuilder();
        for (var i = 0; i < _types.Length; i++)
        {
            if ((found & (1 << i)) == 0)
                continue;
            if (reason.Length > 0)
                reason.Append(--count == 1 ? " and " : ", ");
            reason.Append(_types[i].Name);
        }
        reason[0] = char.ToUpperInvariant(reason[0]);
        return reason.Append(" detected").ToString();
    }

    /// <inheritdoc />
    public IReadOnlyList<RedactionSpan> FindSpans(string text)
    {
        var spans = new List<RedactionSpan>();
        foreach (var (pattern, entityType, _, severity) in _types)
        {
            RedactionSpanCollector.Collect(pattern(), entityType, text, spans, severity);
        }
        return RedactionSpanCollector.Normalize(spans);
    }

    private static ValueTask<DetectionResult> Hit(Severity severity, string reason)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, reason));
}
