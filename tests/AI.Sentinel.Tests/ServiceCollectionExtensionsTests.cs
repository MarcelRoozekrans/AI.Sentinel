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

    [Fact]
    public void AddAISentinel_DoesNotDuplicateDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var duplicates = provider.GetServices<IDetector>()
            .GroupBy(d => d.GetType())
            .Where(g => g.Count() > 1)
            .Select(g => g.Key.Name)
            .ToList();

        Assert.Empty(duplicates);
    }
}
