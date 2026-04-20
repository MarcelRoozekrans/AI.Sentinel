using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class AgentProbingDetector() : StubDetector("OPS-06", DetectorCategory.Operational) { }
