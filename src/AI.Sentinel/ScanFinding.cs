using AI.Sentinel.Detection;

namespace AI.Sentinel;

/// <summary>One detection of a scan and the action <see cref="SentinelOptions.EffectiveAction"/> gives it.</summary>
/// <param name="Detection">The non-clean detection.</param>
/// <param name="Action">Its effective action, after any per-detector override.</param>
internal readonly record struct ScanFinding(DetectionResult Detection, SentinelAction Action);
