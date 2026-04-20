using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class CrossAgentContradictionDetector() : StubDetector("HAL-03", DetectorCategory.Hallucination) { }
