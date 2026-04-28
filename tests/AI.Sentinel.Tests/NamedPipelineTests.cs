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
}
