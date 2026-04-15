using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
namespace AI.Sentinel.Detectors.Operational;

public sealed class ContextCollapseDetector()   : StubDetector("OPS-03", DetectorCategory.Operational) { }
public sealed class AgentProbingDetector()      : StubDetector("OPS-04", DetectorCategory.Operational) { }
public sealed class QueryIntentDetector()       : StubDetector("OPS-05", DetectorCategory.Operational) { }
public sealed class ResponseCoherenceDetector() : StubDetector("OPS-08", DetectorCategory.Operational) { }
