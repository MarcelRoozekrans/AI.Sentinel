using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PiiLeakageDetector : ILlmEscalatingDetector
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
        @"(?:BSN|burgerservicenummer)\s*[:=]?\s*\d{9}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BsnPattern();

    [GeneratedRegex(
        @"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex UkNinoPattern();

    [GeneratedRegex(
        @"passport\s*[:=]?\s*[A-Z]{1,2}\d{6,9}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PassportPattern();

    [GeneratedRegex(
        @"(?:Steuer-?ID|tax\s+id)\s*[:=]?\s*\d{2}\s?\d{3}\s?\d{5}\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DeTaxIdPattern();

    // --- Medium ---

    [GeneratedRegex(
        @"\b[A-Z][a-z]+\s[A-Z][a-z]+\b.{0,30}\b[\w.]+@[\w.]+\.\w{2,}\b",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex EmailWithNamePattern();

    [GeneratedRegex(
        @"(?<!\d)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}\b|\(?\d{1,4}\)?[\s.-]\d{3,4}[\s.-]?\d{4}\b)",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PhonePattern();

    [GeneratedRegex(
        @"(?:born|DOB|date\s+of\s+birth)\s*[:=]?\s*\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b",
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
        if (EmailWithNamePattern().IsMatch(text))
            return Hit(Severity.Medium, "Email with name detected");
        if (PhonePattern().IsMatch(text))
            return Hit(Severity.Medium, "Phone number detected");
        if (DobPattern().IsMatch(text))
            return Hit(Severity.Medium, "Date of birth detected");

        return ValueTask.FromResult(_clean);
    }

    private static ValueTask<DetectionResult> Hit(Severity severity, string reason)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity, reason));
}
