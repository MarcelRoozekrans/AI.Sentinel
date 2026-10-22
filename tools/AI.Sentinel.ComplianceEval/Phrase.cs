using System.Text.Json;

namespace AI.Sentinel.ComplianceEval;

/// <summary>One entry of a phrase file: <c>compliance-phrases.json</c>, <c>everyday-prompts.json</c> or
/// <c>security-phrases.json</c>.</summary>
/// <param name="Detector">The detector the phrase was written for, or <c>-</c> for none.</param>
/// <param name="Text">The request or document text.</param>
/// <param name="Expected"><c>positive</c> for a paraphrased prohibited request or attack; <c>near-miss</c>,
/// <c>everyday</c> or <c>benign</c> for a legitimate text, which must not fire.</param>
/// <param name="Added">The release that added the phrase, such as <c>3.1</c>, or <see langword="null"/> for a phrase
/// of the original evaluation.</param>
internal sealed record Phrase(string Detector, string Text, string Expected, string? Added)
{
    /// <summary>Whether the phrase is a prohibited request that should fire.</summary>
    public bool IsPositive => string.Equals(Expected, "positive", StringComparison.Ordinal);

    /// <summary>The text as a Markdown table cell shows it, marked <c>(new in 3.1)</c> when the phrase was added later.
    /// A <c>|</c> in the text is escaped as <c>\|</c>, or it would split the cell.</summary>
    public string Display
    {
        get
        {
            var text = Text.Replace("|", "\\|", StringComparison.Ordinal);
            return Added is null ? text : $"{text} (new in {Added})";
        }
    }

    /// <summary>Reads a phrase file: <c>compliance-phrases.json</c> and <c>security-phrases.json</c>, which the unit
    /// tests also guard, or <c>everyday-prompts.json</c>. The <c>added</c> property is optional.</summary>
    public static Phrase[] Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return
        [
            .. document.RootElement.GetProperty("phrases").EnumerateArray().Select(e => new Phrase(
                e.GetProperty("detector").GetString()!,
                e.GetProperty("phrase").GetString()!,
                e.GetProperty("expected").GetString()!,
                e.TryGetProperty("added", out var added) ? added.GetString() : null)),
        ];
    }
}
