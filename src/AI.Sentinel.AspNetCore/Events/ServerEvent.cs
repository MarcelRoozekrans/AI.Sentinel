namespace AI.Sentinel.AspNetCore.Events;

/// <summary>An event as the server keeps it: the allowlisted fields and a code in place of the developer. Never the command,
/// paths or tool input (ADR-240).</summary>
internal sealed record ServerEvent(
    string Id,
    string Organisation,
    string Developer,
    DateTimeOffset At,
    DateTimeOffset ReceivedAt,
    string ToolKind,
    string Outcome,
    IReadOnlyList<string> Policies,
    string? PolicyVersion,
    string? DecidedAt,
    string? Node,
    string? Cli,
    string? Session,
    string? Detector,
    string? Severity,
    IReadOnlyDictionary<string, int> Redactions,
    string? Reason,
    string Visibility = ServerEvent.TeamsOnly)
{
    /// <summary>The visibility of a record stored when its node did not show names.</summary>
    public const string TeamsOnly = "teams";

    /// <summary>The visibility of a record stored when its node showed names.</summary>
    public const string WithNames = "names";

    /// <summary>The outcome of a call that was stopped.</summary>
    public const string Blocked = "deny";

    public bool IsBlocked => string.Equals(Outcome, Blocked, StringComparison.Ordinal);
}
