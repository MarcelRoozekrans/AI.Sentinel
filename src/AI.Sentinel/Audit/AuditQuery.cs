using AI.Sentinel.Detection;

namespace AI.Sentinel.Audit;

/// <summary>
/// Filters for <see cref="IAuditStore.QueryAsync"/>. Set only the filters you need with an object
/// initializer, for example <c>new AuditQuery { MinSeverity = Severity.High, PageSize = 50 }</c>.
/// </summary>
public sealed record AuditQuery
{
    /// <summary>Only entries at or above this severity. <see langword="null"/> returns every severity.</summary>
    public Severity? MinSeverity { get; init; }

    /// <summary>Only entries timestamped at or after this instant.</summary>
    public DateTimeOffset? From { get; init; }

    /// <summary>Only entries timestamped at or before this instant.</summary>
    public DateTimeOffset? To { get; init; }

    /// <summary>The maximum number of entries to return. Defaults to 200.</summary>
    public int PageSize { get; init; } = 200;

    /// <summary>When <see langword="true"/>, entries are returned newest first.</summary>
    public bool Reverse { get; init; }

    /// <summary>Only entries recorded for this session.</summary>
    public string? SessionId { get; init; }

    /// <summary>Only entries written by this tool, compared case-insensitively. See <see cref="AuditSources"/>.</summary>
    public string? Source { get; init; }
}
