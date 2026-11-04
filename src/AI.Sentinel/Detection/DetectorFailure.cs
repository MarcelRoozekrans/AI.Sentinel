using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>A detector that did not run to completion in a scan, and why. It never carries an exception message
/// or any part of the scanned text.</summary>
/// <param name="Detector">The detector that was affected.</param>
/// <param name="Kind">What went wrong.</param>
public readonly record struct DetectorFailure(DetectorId Detector, DetectorFailureKind Kind);
