using AI.Sentinel.Detection;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// The outcome a policy or a profile sets per finding severity, in place of or next to the <c>SENTINEL_HOOK_ON_*</c>
/// variables (#655). A severity that is not in the map has no outcome set here. The outcomes are those of #670: deny,
/// ask, guidance, allow and defer. The older action names are accepted too, so a profile's severity defaults read the
/// same way: block is deny, warn and alert are guidance, quarantine is deny, and log and passthrough are defer.
/// </summary>
internal sealed class SeverityActions
{
    private readonly Dictionary<Severity, DecisionOutcome> _bySeverity;

    private SeverityActions(Dictionary<Severity, DecisionOutcome> bySeverity) => _bySeverity = bySeverity;

    /// <summary>A map that sets nothing.</summary>
    public static SeverityActions None { get; } = new([]);

    /// <summary>True when no severity has an outcome.</summary>
    public bool IsEmpty => _bySeverity.Count == 0;

    /// <summary>Reads severity names mapped to action names, such as <c>high</c> to <c>guidance</c>. An entry with an empty
    /// key is the placeholder the host rules declare, and is skipped.</summary>
    /// <exception cref="FormatException">A severity or an action name is not known.</exception>
    public static SeverityActions Parse(IEnumerable<KeyValuePair<string, string>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var map = new Dictionary<Severity, DecisionOutcome>();
        foreach (var (name, action) in entries)
        {
            if (name.Length == 0)
            {
                continue;
            }

            var severity = ParseSeverity(name);
            var outcome = ParseOutcome(action);
            map[severity] = map.TryGetValue(severity, out var seen) ? DecisionOutcomes.Strictest(seen, outcome) : outcome;
        }

        return map.Count == 0 ? None : new SeverityActions(map);
    }

    /// <summary>The severity defaults of a signed profile, read as a policy's severity outcomes are.</summary>
    /// <exception cref="FormatException">A severity or an action name is not known.</exception>
    public static SeverityActions FromProfile(PolicyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return Parse(profile.SeverityDefaults);
    }

    /// <summary>The map as severity names and outcome names, the form <see cref="Parse"/> reads back.</summary>
    public IEnumerable<KeyValuePair<string, string>> Entries() =>
        _bySeverity.Select(e => new KeyValuePair<string, string>(e.Key.ToString().ToLowerInvariant(), DecisionOutcomes.Name(e.Value)));

    /// <summary>The outcome set for <paramref name="severity"/>, when there is one.</summary>
    public bool TryGet(Severity severity, out DecisionOutcome outcome) => _bySeverity.TryGetValue(severity, out outcome);

    /// <summary>The two maps in one: where both set a severity the stricter outcome stands.</summary>
    public static SeverityActions Strictest(SeverityActions a, SeverityActions b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (a.IsEmpty)
        {
            return b;
        }

        if (b.IsEmpty)
        {
            return a;
        }

        var map = new Dictionary<Severity, DecisionOutcome>(a._bySeverity);
        foreach (var (severity, outcome) in b._bySeverity)
        {
            map[severity] = map.TryGetValue(severity, out var seen) ? DecisionOutcomes.Strictest(seen, outcome) : outcome;
        }

        return new SeverityActions(map);
    }

    private static Severity ParseSeverity(string name) => name.ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => throw new FormatException($"'{name}' is not a severity; use critical, high, medium or low"),
    };

    private static DecisionOutcome ParseOutcome(string action) => action.ToLowerInvariant() switch
    {
        "deny" or "block" or "quarantine" => DecisionOutcome.Deny,
        "ask" => DecisionOutcome.Ask,
        "guidance" or "warn" or "alert" => DecisionOutcome.Guidance,
        "allow" => DecisionOutcome.Allow,
        "defer" or "log" or "passthrough" => DecisionOutcome.Defer,
        _ => throw new FormatException($"'{action}' is not a severity action; use deny, ask, guidance, allow or defer"),
    };
}
