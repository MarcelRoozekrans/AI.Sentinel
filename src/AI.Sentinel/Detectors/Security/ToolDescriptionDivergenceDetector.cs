using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

// Needs tool descriptor snapshot added to SentinelContext (v1.1 follow-up)
// before a rule-based first pass is possible. StubDetector wires
// ILlmEscalatingDetector for the rare case where a divergent description
// leaks into message text.
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ToolDescriptionDivergenceDetector() : StubDetector("SEC-18", DetectorCategory.Security) { }
