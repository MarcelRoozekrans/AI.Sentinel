using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class MemoryCorruptionDetector() : StubDetector("SEC-11", DetectorCategory.Security) { }
