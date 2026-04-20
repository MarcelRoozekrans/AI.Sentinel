using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SourceGroundingDetector() : StubDetector("HAL-04", DetectorCategory.Hallucination) { }
