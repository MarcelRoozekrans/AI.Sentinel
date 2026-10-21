using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class SentinelOptionsDisableDetectorTests
{
    // Red: key the table by Id only.
    [Fact]
    public void Disable_by_type_name_turns_the_detector_off()
    {
        var opts = new SentinelOptions();

        opts.DisableDetector("PromptInjectionDetector");

        Assert.False(opts.GetDetectorConfigurations()[typeof(PromptInjectionDetector)].Enabled);
    }

    // Red: key the table by name only.
    [Fact]
    public void Disable_by_id_turns_the_detector_off()
    {
        var opts = new SentinelOptions();

        opts.DisableDetector("SEC-01");

        Assert.False(opts.GetDetectorConfigurations()[typeof(PromptInjectionDetector)].Enabled);
    }

    // Red: return opts without throwing.
    [Fact]
    public void Disable_with_an_unknown_name_throws_naming_it()
    {
        var ex = Assert.Throws<ArgumentException>(() => new SentinelOptions().DisableDetector("NoSuchDetector"));

        Assert.Contains("'NoSuchDetector'", ex.Message);
    }

    // Red: create the configuration before resolving.
    [Fact]
    public void TryDisable_with_an_unknown_name_returns_false_and_changes_nothing()
    {
        var opts = new SentinelOptions();

        Assert.False(opts.TryDisableDetector("NoSuchDetector"));
        Assert.Empty(opts.GetDetectorConfigurations());
    }

    // Red: return false on success.
    [Fact]
    public void TryDisable_with_a_known_name_returns_true()
    {
        var opts = new SentinelOptions();

        Assert.True(opts.TryDisableDetector("SEC-01"));
        Assert.False(opts.GetDetectorConfigurations()[typeof(PromptInjectionDetector)].Enabled);
    }

    // Red: drop one row from the table.
    [Fact]
    public void The_table_lists_every_official_detector_with_its_id()
    {
        using var provider = new ServiceCollection().AddAISentinel(_ => { }).BuildServiceProvider();
        var detectors = provider.GetServices<IDetector>().ToList();

        Assert.NotEmpty(detectors);
        foreach (var d in detectors)
        {
            Assert.True(OfficialDetectors.TryResolve(d.GetType().Name, out var byName), d.GetType().Name);
            Assert.Equal(d.GetType(), byName);
            Assert.True(OfficialDetectors.TryResolve(d.Id.Value, out var byId), d.Id.Value);
            Assert.Equal(d.GetType(), byId);
        }
        Assert.Equal(detectors.Count, OfficialDetectors.Count);
    }

    // Red: use OrdinalIgnoreCase.
    [Fact]
    public void Disabling_is_case_sensitive()
    {
        Assert.False(new SentinelOptions().TryDisableDetector("promptinjectiondetector"));
    }
}
