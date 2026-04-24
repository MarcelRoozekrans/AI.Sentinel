using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class ShorthandEmergenceDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-30");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    private static readonly HashSet<string> CommonAcronyms = new(StringComparer.Ordinal)
    {
        "API", "JSON", "HTTP", "HTTPS", "URL", "SDK", "CLI", "AI", "LLM", "MCP",
        "REST", "SQL", "XML", "CSV", "JWT", "UUID", "PDF", "HTML", "CSS", "UI",
        "UX", "EOF", "UTF", "ASCII", "GPU", "CPU", "RAM", "SSD", "AWS", "GCP",
        "CI", "CD", "PR", "TDD", "DI", "IOT", "ML", "NLP", "IPC", "RPC",
    };

    [GeneratedRegex(@"\b[A-Z]{3,}\b",
        RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex UppercaseTokenPattern();

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var unknownCount = UppercaseTokenPattern().Matches(ctx.TextContent)
            .Select(m => m.Value)
            .Where(t => !CommonAcronyms.Contains(t))
            .Distinct(StringComparer.Ordinal)
            .Count();

        return unknownCount switch
        {
            >= 5 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"{unknownCount} unknown all-caps tokens — possible emergent shorthand")),
            >= 3 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"{unknownCount} unknown all-caps tokens — possible emergent shorthand")),
            _    => ValueTask.FromResult(_clean),
        };
    }
}
