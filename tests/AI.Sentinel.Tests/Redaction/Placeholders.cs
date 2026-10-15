using System.Text.RegularExpressions;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>
/// Placeholders carry a random per-call tag, such as <c>[EMAIL_1_k3f9x2]</c>. Tests that only care about type and
/// number compare the untagged form, and scripted models write the untagged form and echo the tagged token they saw.
/// </summary>
internal static partial class Placeholders
{
    [GeneratedRegex(@"\[(?<name>[A-Z0-9_]+_\d+)_[a-z][a-z0-9]{5}\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Tagged();

    [GeneratedRegex(@"\[(?<name>[A-Z0-9_]+_\d+)\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Untagged();

    [GeneratedRegex(@"\[(?<name>[A-Z0-9_]+_\d+)(?:_[a-z][a-z0-9]{5})?\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Any();

    [GeneratedRegex(@"_\d+_(?<tag>[a-z][a-z0-9]{5})\]", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, matchTimeoutMilliseconds: 1000)]
    private static partial Regex TagPattern();

    [GeneratedRegex(@"(?<=_\d+)\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NumberEnd();

    /// <summary>The tag of the first placeholder in <paramref name="seen"/>; null when there is none.</summary>
    public static string? TagOf(string seen)
    {
        var m = TagPattern().Match(seen);
        return m.Success ? m.Groups["tag"].Value : null;
    }

    /// <summary>
    /// Adds <paramref name="tag"/> to every placeholder end in <paramref name="text"/>, also when the text is only a
    /// piece of one: <c>IL_1] today</c> becomes <c>IL_1_k3f9x2] today</c>. For scripted streams split mid-token.
    /// </summary>
    public static string AddTag(string text, string tag) => NumberEnd().Replace(text, "_" + tag + "]");

    /// <summary><paramref name="text"/> with every tag removed: <c>[EMAIL_1_k3f9x2]</c> becomes <c>[EMAIL_1]</c>.</summary>
    public static string Untag(string? text) => Tagged().Replace(text ?? string.Empty, "[${name}]");

    /// <summary>The first token in <paramref name="seen"/> that untags to <paramref name="untagged"/>, such as
    /// <c>[EMAIL_1]</c>; null when there is none.</summary>
    public static string? FirstSeen(string seen, string untagged)
    {
        foreach (Match m in Any().Matches(seen))
        {
            if (string.Equals("[" + m.Groups["name"].Value + "]", untagged, StringComparison.Ordinal))
            {
                return m.Value;
            }
        }
        return null;
    }

    /// <summary>
    /// Replaces each untagged placeholder in <paramref name="scripted"/> with the first tagged token of the same
    /// type and number in <paramref name="seen"/>, as a model repeating a placeholder from its prompt would.
    /// One with no such token stays as written.
    /// </summary>
    public static string Echo(string scripted, string seen) =>
        Untagged().Replace(scripted, m => FirstSeen(seen, m.Value) ?? m.Value);
}
