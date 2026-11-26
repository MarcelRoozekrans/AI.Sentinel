using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <param name="Rejection"><see cref="AdminAuditRejection.None"/> when the export verified.</param>
/// <param name="FirstBrokenEntryId">Set for <see cref="AdminAuditRejection.ChainBroken"/>: the first entry that breaks the chain.</param>
/// <param name="SignedCount">The entry count the signed head states, when the head was readable.</param>
/// <param name="ExportedAt">The export time the signed head states, when the head was readable.</param>
/// <param name="LastHash">The last hash the signed head states.</param>
internal sealed record AdminAuditVerification(
    AdminAuditRejection Rejection,
    string? FirstBrokenEntryId,
    long SignedCount,
    DateTimeOffset? ExportedAt,
    string? LastHash)
{
    public bool IsValid => Rejection == AdminAuditRejection.None;
}
