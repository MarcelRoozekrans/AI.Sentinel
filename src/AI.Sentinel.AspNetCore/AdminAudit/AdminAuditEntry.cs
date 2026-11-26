using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>
/// One administrative action. It holds who, what, on which target and through which channel, and nothing else:
/// there is no field for file contents, tokens or tool input. Target is an identifier, never content.
/// </summary>
internal sealed record AdminAuditEntry(
    string Id,
    DateTimeOffset Timestamp,
    string Organisation,
    string Action,
    string Actor,
    string Target,
    string Channel,
    string? PreviousHash,
    string Hash)
{
    /// <summary>Longest accepted actor, target or organisation. A longer value is not an identifier.</summary>
    public const int MaxFieldLength = 256;

    /// <summary>The <see cref="AuditEntry"/> that <see cref="AuditHashChain"/> hashes. The organisation sits in the
    /// session field so the hash binds the entry to its organisation.</summary>
    public AuditEntry ToChainEntry() => new(Id, Timestamp, Hash, PreviousHash, Severity.None, Action, Target)
    {
        PolicyCode = Channel,
        SessionId = Organisation,
        Source = Actor,
    };

    public static AdminAuditEntry FromChainEntry(AuditEntry e) =>
        new(e.Id, e.Timestamp, e.SessionId ?? string.Empty, e.DetectorId, e.Source ?? string.Empty, e.Summary,
            e.PolicyCode ?? string.Empty, e.PreviousHash, e.Hash);

    /// <summary>Throws when a value cannot be an identifier: empty, too long, or holding a control character such as a newline.</summary>
    public static void CheckField(string? value, string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, name);
        if (value.Length > MaxFieldLength)
        {
            throw new ArgumentException($"{name} is longer than {MaxFieldLength} characters. The audit log holds identifiers, not content.", name);
        }
        foreach (var c in value)
        {
            if (char.IsControl(c))
            {
                throw new ArgumentException($"{name} holds a control character. The audit log holds identifiers, not content.", name);
            }
        }
    }
}
