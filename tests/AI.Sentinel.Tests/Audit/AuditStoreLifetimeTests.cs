using AI.Sentinel.Audit;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditStoreLifetimeTests
{
    [Fact]
    public void AddAISentinel_RegistersAuditStoreAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        var descriptor = services.Single(d => d.ServiceType == typeof(IAuditStore));
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
    }
}
