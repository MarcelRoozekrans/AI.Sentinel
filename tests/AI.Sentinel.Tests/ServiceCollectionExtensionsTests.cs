using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAISentinel_RegistersAllDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var detectors = provider.GetServices<IDetector>().ToList();
        Assert.True(detectors.Count >= 43, $"Expected >= 43 detectors, got {detectors.Count}");
    }
}
