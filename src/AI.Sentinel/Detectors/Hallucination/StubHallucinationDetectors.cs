using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
namespace AI.Sentinel.Detectors.Hallucination;

public sealed class CrossAgentContradictionDetector() : StubDetector("HAL-02", DetectorCategory.Hallucination) { }
public sealed class SourceGroundingDetector()         : StubDetector("HAL-03", DetectorCategory.Hallucination) { }
public sealed class ConfidenceDecayDetector()         : StubDetector("HAL-04", DetectorCategory.Hallucination) { }
