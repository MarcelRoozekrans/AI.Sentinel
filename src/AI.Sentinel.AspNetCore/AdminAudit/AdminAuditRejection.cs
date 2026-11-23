using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.AdminAudit;

internal enum AdminAuditRejection
{
    None,
    Malformed,
    WrongOrganisation,
    UnknownKey,
    BadSignature,
    ChainBroken,
    StartMissing,
    HeadMismatch,
    OlderThanCheckpoint,
    CheckpointNotContained,
}
