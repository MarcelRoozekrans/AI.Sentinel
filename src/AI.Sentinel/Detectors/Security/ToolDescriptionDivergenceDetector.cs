using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

/// <summary>SEC-18: a tool description that changed at runtime. Not implemented yet: it always returns Clean.</summary>
/// <remarks>
/// A real check needs a snapshot of the tool descriptors on <see cref="SentinelContext"/>, which does not
/// exist yet. Escalation cannot stand in for it, see <see cref="StubDetector"/>. Internal because a detector
/// that never fires has no value to a consumer, and implementing SEC-18 will change its shape.
/// </remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
internal sealed class ToolDescriptionDivergenceDetector() : StubDetector("SEC-18", DetectorCategory.Security) { }
