using System.Text.Json;

namespace AI.Sentinel.ComplianceEval;

/// <summary>One entry of <c>compliance-phrases.json</c>.</summary>
/// <param name="Detector">The detector the phrase was written for.</param>
/// <param name="Text">The request text.</param>
/// <param name="Expected"><c>positive</c> for a paraphrased prohibited request; <c>near-miss</c> or <c>everyday</c>
/// for a legitimate request, which must not fire.</param>
internal sealed record Phrase(string Detector, string Text, string Expected)
{
    /// <summary>Whether the phrase is a prohibited request that should fire.</summary>
    public bool IsPositive => string.Equals(Expected, "positive", StringComparison.Ordinal);

    /// <summary>Reads a phrase file: <c>compliance-phrases.json</c>, which the unit tests also guard, or
    /// <c>everyday-prompts.json</c>.</summary>
    public static Phrase[] Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return
        [
            .. document.RootElement.GetProperty("phrases").EnumerateArray().Select(e => new Phrase(
                e.GetProperty("detector").GetString()!,
                e.GetProperty("phrase").GetString()!,
                e.GetProperty("expected").GetString()!)),
        ];
    }
}
