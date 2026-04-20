using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class PersonaDriftDetector() : StubDetector("OPS-13", DetectorCategory.Operational) { }
