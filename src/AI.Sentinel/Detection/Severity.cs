namespace AI.Sentinel.Detection;

/// <summary>How serious a detection is. Members are ordered, so comparisons such as
/// <c>severity &gt;= Severity.High</c> are meaningful.</summary>
/// <remarks>The numeric values are persisted: they are an input to <see cref="Audit.AuditHashChain"/>
/// and stored as integers by the SQLite audit store. They must never change, and a new member must
/// take a new value rather than renumber an existing one.</remarks>
public enum Severity
{
    /// <summary>No threat.</summary>
    None = 0,

    /// <summary>Low severity.</summary>
    Low = 1,

    /// <summary>Medium severity.</summary>
    Medium = 2,

    /// <summary>High severity.</summary>
    High = 3,

    /// <summary>Critical severity.</summary>
    Critical = 4,
}
