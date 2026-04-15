using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
namespace AI.Sentinel.Detectors.Security;

public sealed class EntropyCovertChannelDetector()    : StubDetector("SEC-05", DetectorCategory.Security) { }
public sealed class MemoryCorruptionDetector()        : StubDetector("SEC-06", DetectorCategory.Security) { }
public sealed class UnauthorizedAccessDetector()      : StubDetector("SEC-07", DetectorCategory.Security) { }
public sealed class ShadowServerDetector()            : StubDetector("SEC-08", DetectorCategory.Security) { }
public sealed class InformationFlowDetector()         : StubDetector("SEC-09", DetectorCategory.Security) { }
public sealed class PhantomCitationSecurityDetector() : StubDetector("SEC-10", DetectorCategory.Security) { }
public sealed class GovernanceGapDetector()           : StubDetector("SEC-11", DetectorCategory.Security) { }
public sealed class CovertChannelDetector()           : StubDetector("SEC-12", DetectorCategory.Security) { }
public sealed class IndirectInjectionDetector()       : StubDetector("SEC-14", DetectorCategory.Security) { }
public sealed class AgentImpersonationDetector()      : StubDetector("SEC-15", DetectorCategory.Security) { }
public sealed class SupplyChainPoisoningDetector()    : StubDetector("SEC-17", DetectorCategory.Security) { }
