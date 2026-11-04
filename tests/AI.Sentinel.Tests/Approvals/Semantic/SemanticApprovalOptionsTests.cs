using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Semantic;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Semantic;

public class SemanticApprovalOptionsTests
{
    [Fact]
    public void Registration_KeepsOrderAndSpec()
    {
        var opts = new SentinelOptions();
        opts.RequireSemanticApproval("Bash", s => { s.BackendBinding = "Operator"; s.GrantDuration = TimeSpan.FromMinutes(3); s.Paths("$.command"); })
            .RequireSemanticApproval("db_*", s => s.BackendBinding = "Dba");

        var tools = opts.GetSemanticApprovals().Tools;
        Assert.Equal(new[] { "Bash", "db_*" }, tools.Select(t => t.Pattern).ToArray());
        Assert.Equal("Operator", tools[0].Spec.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(3), tools[0].Spec.GrantDuration);
        Assert.Single(tools[0].Spec.ParsedPaths!);
        Assert.Null(tools[1].Spec.ParsedPaths);
        Assert.True(tools[1].Spec.RequireJustification);
        Assert.Equal(TimeSpan.FromMinutes(5), tools[1].Spec.WaitTimeout);
    }

    [Fact]
    public void DuplicatePattern_Throws()
    {
        var opts = new SentinelOptions();
        opts.RequireSemanticApproval("Bash", s => s.BackendBinding = "A");
        Assert.Throws<InvalidOperationException>(() => opts.RequireSemanticApproval("Bash", s => s.BackendBinding = "B"));
    }

    [Fact]
    public void MissingBackendBinding_Throws()
    {
        var opts = new SentinelOptions();
        Assert.Throws<InvalidOperationException>(() => opts.RequireSemanticApproval("Bash", _ => { }));
    }

    [Theory]
    [InlineData(0f)]
    [InlineData(-0.1f)]
    [InlineData(1.01f)]
    [InlineData(float.NaN)]
    public void ThresholdOutOfRange_Throws(float threshold)
    {
        var opts = new SentinelOptions();
        Assert.Throws<InvalidOperationException>(() =>
            opts.RequireSemanticApproval("Bash", s => { s.BackendBinding = "A"; s.Threshold = threshold; }));
    }

    [Fact]
    public void ThresholdOne_IsAccepted()
    {
        var opts = new SentinelOptions();
        opts.RequireSemanticApproval("Bash", s => { s.BackendBinding = "A"; s.Threshold = 1f; });
        Assert.Equal(1f, opts.GetSemanticApprovals().Tools[0].Spec.Threshold);
    }

    [Fact]
    public void EmptyPaths_Throws()
        => Assert.Throws<ArgumentException>(() => new SemanticApprovalSpec().Paths());

    [Fact]
    public void BadPath_ThrowsNamingThePath()
    {
        var ex = Assert.Throws<ArgumentException>(() => new SemanticApprovalSpec().Paths("$.ok", "$[bad"));
        Assert.Contains("$[bad", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Settings_RecordExamplesAndReplace()
    {
        var opts = new SentinelOptions();
        opts.ConfigureSemanticApprovals(s => { s.Threshold = 0.7f; s.ReplaceExamples = true; s.AddExamples("a", "b").AddExamples("c"); });

        var settings = opts.GetSemanticApprovals().Settings;
        Assert.Equal(0.7f, settings.Threshold);
        Assert.True(settings.ReplaceExamples);
        Assert.Equal(new[] { "a", "b", "c" }, settings.AddedExamples);
    }

    [Theory]
    [InlineData(0f)]
    [InlineData(-0.1f)]
    [InlineData(1.01f)]
    [InlineData(5f)]
    [InlineData(float.NaN)]
    public void GlobalThresholdOutOfRange_Throws(float threshold)
    {
        var opts = new SentinelOptions();
        Assert.Throws<InvalidOperationException>(() => opts.ConfigureSemanticApprovals(s => s.Threshold = threshold));
    }

    [Fact]
    public void GlobalThresholdOne_IsAccepted()
    {
        var opts = new SentinelOptions();
        opts.ConfigureSemanticApprovals(s => s.Threshold = 1f);
        Assert.Equal(1f, opts.GetSemanticApprovals().Settings.Threshold);
    }

    [Fact]
    public void NullExample_ThrowsArgumentNull()
        => Assert.Throws<ArgumentNullException>(() => new SemanticApprovalSettings().AddExamples("ok", null!));

    [Fact]
    public void NullExamplesArray_ThrowsArgumentNull()
        => Assert.Throws<ArgumentNullException>(() => new SemanticApprovalSettings().AddExamples(null!));

    [Fact]
    public void BlankExample_Throws()
        => Assert.Throws<ArgumentException>(() => new SemanticApprovalSettings().AddExamples("ok", " "));

    [Fact]
    public void AddAISentinel_WithOnlySemanticTools_RegistersApprovalStore()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.RequireSemanticApproval("Bash", s => s.BackendBinding = "Operator"));
        Assert.Contains(services, d => d.ServiceType == typeof(IApprovalStore));
    }
}
