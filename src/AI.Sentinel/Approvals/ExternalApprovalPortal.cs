namespace AI.Sentinel.Approvals;

/// <summary>
/// Marker a host registers as a singleton when its approvals are decided in an external portal
/// and no <see cref="IApprovalAdmin"/> store is available locally. The dashboard then shows the
/// "managed externally" message instead of "No approval store configured".
/// </summary>
internal sealed class ExternalApprovalPortal;
