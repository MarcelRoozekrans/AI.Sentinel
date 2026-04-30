using AI.Sentinel;
using AI.Sentinel.Approvals.Configuration;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Configuration;

public class ApprovalBackendSelectorTests
{
    private static ApprovalConfig MakeConfig(
        string backend = "in-memory",
        Dictionary<string, ApprovalToolConfig>? tools = null,
        int defaultGrantMinutes = 15) =>
        new(
            backend,
            TenantId: string.Equals(backend, "entra-pim", StringComparison.Ordinal) ? "test-tenant" : null,
            DatabasePath: string.Equals(backend, "sqlite", StringComparison.Ordinal) ? "/tmp/test.db" : null,
            defaultGrantMinutes,
            DefaultJustificationTemplate: "{tool}",
            IncludeConversationContext: true,
            Tools: tools ?? new Dictionary<string, ApprovalToolConfig>(StringComparer.Ordinal));

    [Fact]
    public void GetBackend_InMemory_ReturnsInMemoryKind() =>
        Assert.Equal(ApprovalBackendKind.InMemory, ApprovalBackendSelector.GetBackend(MakeConfig("in-memory")));

    [Fact]
    public void GetBackend_Sqlite_ReturnsSqliteKind() =>
        Assert.Equal(ApprovalBackendKind.Sqlite, ApprovalBackendSelector.GetBackend(MakeConfig("sqlite")));

    [Fact]
    public void GetBackend_EntraPim_ReturnsEntraPimKind() =>
        Assert.Equal(ApprovalBackendKind.EntraPim, ApprovalBackendSelector.GetBackend(MakeConfig("entra-pim")));

    [Fact]
    public void GetBackend_None_ReturnsNoneKind() =>
        Assert.Equal(ApprovalBackendKind.None, ApprovalBackendSelector.GetBackend(MakeConfig("none")));

    [Fact]
    public void GetBackend_NullConfig_Throws() =>
        Assert.Throws<ArgumentNullException>(() => ApprovalBackendSelector.GetBackend(null!));

    [Fact]
    public void Configure_AddsRequireApprovalBindings_PerTool()
    {
        var tools = new Dictionary<string, ApprovalToolConfig>(StringComparer.Ordinal)
        {
            ["delete_database"] = new("DBA", GrantMinutes: 30, RequireJustification: null),
            ["deploy_*"]        = new("DeployApprover", GrantMinutes: null, RequireJustification: false),
        };
        var opts = new SentinelOptions();

        ApprovalBackendSelector.Configure(opts, MakeConfig(tools: tools, defaultGrantMinutes: 15));

        var bindings = opts.GetAuthorizationBindings();
        Assert.Equal(2, bindings.Count);

        var deleteBinding = bindings.Single(b => string.Equals(b.Pattern, "delete_database", StringComparison.Ordinal));
        Assert.NotNull(deleteBinding.ApprovalSpec);
        Assert.Equal("DBA", deleteBinding.ApprovalSpec!.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(30), deleteBinding.ApprovalSpec.GrantDuration);
        Assert.True(deleteBinding.ApprovalSpec.RequireJustification);

        var deployBinding = bindings.Single(b => string.Equals(b.Pattern, "deploy_*", StringComparison.Ordinal));
        Assert.Equal("DeployApprover", deployBinding.ApprovalSpec!.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(15), deployBinding.ApprovalSpec.GrantDuration); // default
        Assert.False(deployBinding.ApprovalSpec.RequireJustification);
    }

    [Fact]
    public void Configure_NullArgs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ApprovalBackendSelector.Configure(null!, MakeConfig()));

        var opts = new SentinelOptions();
        Assert.Throws<ArgumentNullException>(() =>
            ApprovalBackendSelector.Configure(opts, null!));
    }
}
