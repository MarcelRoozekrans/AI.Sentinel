namespace AI.Sentinel.Detection;

/// <summary>
/// Marks a detector whose finding goes up one severity level when it repeats within a session: OPS-13 PersonaDrift
/// and HAL-07 IntraSessionContradiction, where a repeat is drift building up rather than the same topic coming up
/// again.
/// </summary>
/// <remarks>
/// When the detector's result is not clean and the session's audit store holds at least
/// <see cref="Audit.SessionHistory.EscalationThreshold"/> earlier entries of the same detector with a severity above
/// None, the pipeline raises the result one level, at most to Critical, and appends
/// "; repeated in earlier scans of this session" to its reason. It is one step however many hits there are, and the
/// earlier entries are only counted, so escalation never ratchets across turns. A clean result stays clean: escalation
/// refines a finding, it never creates one. The configured <see cref="DetectorConfiguration.SeverityCap"/> still holds,
/// and a semantic result stays under the semantic cap until a reviewer confirms the escalated severity.
/// Internal, because which detectors escalate is the library's call, not a setting.
/// </remarks>
internal interface ISessionEscalatingDetector : IDetector;
