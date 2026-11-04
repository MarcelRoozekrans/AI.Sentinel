using AI.Sentinel.Detection;

namespace AI.Sentinel;

/// <summary>The findings of one screening scan, plus the detectors that did not run to completion in it. The scan
/// sets <see cref="Failures"/> from the pipeline's own list, so a clean screen allocates no list for it.</summary>
internal sealed class ScanFindings : List<ScanFinding>
{
    public IReadOnlyList<DetectorFailure> Failures { get; set; } = [];
}
