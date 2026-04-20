using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SupplyChainPoisoningDetector() : StubDetector("SEC-17", DetectorCategory.Security) { }
