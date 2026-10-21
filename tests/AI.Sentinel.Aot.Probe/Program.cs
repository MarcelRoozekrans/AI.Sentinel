using AI.Sentinel;
using AI.Sentinel.Aot.Probe;
using AI.Sentinel.Detection;
using Microsoft.Extensions.DependencyInjection;

// Roots AddAISentinel and AddDetector<T> under Native AOT. DetectorRegistrationTrimTests publishes
// this project and reads the ILC warnings; run by hand, the binary prints "ok".
var services = new ServiceCollection();
services.AddAISentinel(o => o.AddDetector<ProbeDetector>().AddDetector(_ => new ProbeDetector()));

using var provider = services.BuildServiceProvider();
_ = provider.GetRequiredService<IDetectionPipeline>();
Console.WriteLine("ok");
