using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

public class NamedPipelineTests
{
    [Fact]
    public void AddAISentinel_NullName_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddAISentinel(name: null!, opts => { }));
    }

    [Fact]
    public void AddAISentinel_EmptyName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "", opts => { }));
    }

    [Fact]
    public void AddAISentinel_WhitespaceName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "   ", opts => { }));
    }

    [Fact]
    public void AddAISentinel_DuplicateName_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddAISentinel("strict", opts => { });
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddAISentinel("strict", opts => { }));
        Assert.Contains("strict", ex.Message, StringComparison.Ordinal);
        Assert.Contains("already registered", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAISentinel_Named_RegistersIsolatedSentinelOptions()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);  // default unnamed
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 200);
        services.AddAISentinel("lenient", opts => opts.AuditCapacity = 300);

        var sp = services.BuildServiceProvider();
        var defaultOpts = sp.GetRequiredService<SentinelOptions>();
        var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

        Assert.Equal(100, defaultOpts.AuditCapacity);
        Assert.Equal(200, strictOpts.AuditCapacity);
        Assert.Equal(300, lenientOpts.AuditCapacity);
        Assert.NotSame(defaultOpts, strictOpts);
        Assert.NotSame(strictOpts, lenientOpts);
    }

    [Fact]
    public void AddAISentinel_Named_DefaultPipelineUnaffected()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

        var sp = services.BuildServiceProvider();
        Assert.Equal(100, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
        Assert.NotNull(sp.GetRequiredService<IDetectionPipeline>());
    }

    [Fact]
    public void UseAISentinel_NamedResolvesKeyedPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

        var sp = services.BuildServiceProvider();
        var opts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>("strict");
        var engine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

        Assert.Equal(999, opts.AuditCapacity);
        Assert.NotNull(pipeline);
        Assert.NotNull(engine);
    }

    [Fact]
    public void UseAISentinel_UnknownName_FailsToResolveKeyedService()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        var sp = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() =>
            sp.GetRequiredKeyedService<IDetectionPipeline>("never-registered"));
    }

    [Fact]
    public void UseAISentinel_UnnamedStillResolvesDefaultPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 42);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);
        var sp = services.BuildServiceProvider();

        Assert.Equal(42, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
    }

    [Fact]
    public void Named_ConfigureT_AppliesPerPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddAISentinel("strict", opts =>
            opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High));
        services.AddAISentinel("lenient", opts =>
            opts.Configure<JailbreakDetector>(c => c.Enabled = false));

        var sp = services.BuildServiceProvider();
        var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

        var strictCfg = strictOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];
        var lenientCfg = lenientOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];

        Assert.Equal(Severity.High, strictCfg.SeverityFloor);
        Assert.True(strictCfg.Enabled);
        Assert.Null(lenientCfg.SeverityFloor);
        Assert.False(lenientCfg.Enabled);

        var defaultOpts = sp.GetRequiredService<SentinelOptions>();
        Assert.False(defaultOpts.GetDetectorConfigurations().ContainsKey(typeof(JailbreakDetector)));
    }

    [Fact]
    public void Named_AuditStoreIsShared()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddAISentinel("strict", opts => { });
        services.AddAISentinel("lenient", opts => { });

        var sp = services.BuildServiceProvider();
        var defaultStore = sp.GetRequiredService<IAuditStore>();
        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("strict"));
        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("lenient"));
        Assert.NotNull(defaultStore);
    }

    [Fact]
    public void Named_InterventionEngineIsolated()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Log);
        services.AddAISentinel("strict", opts => opts.OnHigh = SentinelAction.Quarantine);

        var sp = services.BuildServiceProvider();
        var defaultEngine = sp.GetRequiredService<InterventionEngine>();
        var strictEngine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

        Assert.NotSame(defaultEngine, strictEngine);
    }
}
