using System.Text.Json;
using System.Text.RegularExpressions;

namespace AI.Sentinel.Approvals.Conditions;

/// <summary>
/// A <c>when</c> condition: a regex tested against the text found at a JSON path in the tool arguments.
/// Case-sensitive, culture-invariant, <see cref="Regex.IsMatch(string)"/> semantics.
/// </summary>
internal sealed class ArgumentCondition
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private readonly Regex _regex;

    public ArgumentCondition(string jsonPath, string pattern)
    {
        ArgumentNullException.ThrowIfNull(jsonPath);
        ArgumentNullException.ThrowIfNull(pattern);
        Path = ArgumentPath.Parse(jsonPath);
        Pattern = pattern;
        _regex = Compile(pattern);
    }

    /// <summary>The parsed JSON path.</summary>
    public ArgumentPath Path { get; }

    /// <summary>The regex pattern as written.</summary>
    public string Pattern { get; }

    /// <summary>Evaluates the condition against the tool arguments. Never throws.</summary>
    public ConditionResult Evaluate(JsonElement args)
    {
        switch (Path.Resolve(args, out var text))
        {
            case ArgumentPathResult.NotFound:
                return ConditionResult.DoesNotHold;
            case ArgumentPathResult.Unreadable:
                return ConditionResult.Unreadable;
            case ArgumentPathResult.DuplicateKey:
                return ConditionResult.AmbiguousKey;
        }

        try
        {
            return _regex.IsMatch(text) ? ConditionResult.Holds : ConditionResult.DoesNotHold;
        }
        catch (RegexMatchTimeoutException)
        {
            return ConditionResult.TimedOut;
        }
    }

    private static Regex Compile(string pattern)
    {
        try
        {
            try
            {
                return new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
            }
            catch (NotSupportedException)
            {
                return new Regex(pattern, RegexOptions.CultureInvariant, MatchTimeout);
            }
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"Invalid regex '{pattern}': {ex.Message}", nameof(pattern), ex);
        }
    }
}
