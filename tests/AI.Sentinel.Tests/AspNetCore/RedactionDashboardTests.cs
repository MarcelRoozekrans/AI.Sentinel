using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Tests.AspNetCore;

public class RedactionDashboardTests
{
    private static AuditEntry Redaction() =>
        AuditEntryRedactionExtensions.Redaction("SEC-23", new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 }, "session-1");

    private static AuditEntry Threat(Severity severity) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "deadbeef00000000", null, severity, "SEC-01", "threat");

    private static async Task<IHost> BuildHostAsync() =>
        await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                });
                web.Configure(app => app.UseAISentinel("/sentinel"));
            })
            .StartAsync();

    private static async Task<string> GetAsync(IHost host, string path)
    {
        var resp = await host.GetTestClient().GetAsync(path, TestContext.Current.CancellationToken);
        return await resp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task RedactionEntry_NotCountedInSeverityTiles()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(Threat(Severity.High), CancellationToken.None);
        var before = await GetAsync(host, "/sentinel/api/stats");

        await store.AppendAsync(Redaction(), CancellationToken.None);
        var after = await GetAsync(host, "/sentinel/api/stats");

        Assert.Equal(before, after);
    }

    [Fact]
    public async Task RedactionEntry_NotCountedInTrendBuckets()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        var empty = await GetAsync(host, "/sentinel/api/trend");

        await store.AppendAsync(Redaction(), CancellationToken.None);
        var after = await GetAsync(host, "/sentinel/api/trend");

        Assert.Equal(empty, after);
    }

    [Fact]
    public void RedactionEntry_RiskScoreUnchanged()
    {
        var threats = new List<AuditEntry> { Threat(Severity.High) };
        var withRedaction = new List<AuditEntry>(threats) { Redaction(), Redaction() };

        Assert.Equal(
            ThreatRiskScore.Aggregate(DashboardHandlers.BuildScoreInputs(threats)),
            ThreatRiskScore.Aggregate(DashboardHandlers.BuildScoreInputs(withRedaction)));
    }

    [Fact]
    public async Task RedactionEntry_FeedRow_HasRedactedBadge()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(Redaction(), CancellationToken.None);

        var html = await GetAsync(host, "/sentinel/api/feed");

        Assert.Contains("badge redacted", html, StringComparison.Ordinal);
        Assert.Contains("Redacted 1 EMAIL", html, StringComparison.Ordinal);
        Assert.DoesNotContain("severity-none", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RedactedChip_FindsOnlyRedactionEntries()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(Redaction(), CancellationToken.None);
        await store.AppendAsync(Threat(Severity.High), CancellationToken.None);

        var html = await GetAsync(host, "/sentinel/api/feed?filter=redacted");

        Assert.Equal(1, Regex.Count(html, "<tr class=", RegexOptions.None, TimeSpan.FromSeconds(1)));
        Assert.Contains("badge redacted", html, StringComparison.Ordinal);
    }

    // A redaction is not a detection, so the category chips never list it, not even Security for its SEC- id.
    // It stays in the unfiltered feed and under the Redacted chip.
    [Theory]
    [InlineData("security", 1, false)]
    [InlineData("redacted", 1, true)]
    [InlineData(null, 2, true)]
    public async Task CategoryChip_ExcludesRedactionEntries(string? filter, int rows, bool hasRedaction)
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(Redaction(), CancellationToken.None);
        await store.AppendAsync(Threat(Severity.High), CancellationToken.None);

        var html = await GetAsync(host, filter is null ? "/sentinel/api/feed" : "/sentinel/api/feed?filter=" + filter);

        Assert.Equal(rows, Regex.Count(html, "<tr class=", RegexOptions.None, TimeSpan.FromSeconds(1)));
        Assert.Equal(hasRedaction, html.Contains("badge redacted", StringComparison.Ordinal));
    }

    [Fact]
    public void FilterAuditEntries_SecurityCategory_SkipsRedactionOfASecurityDetector()
    {
        var result = new List<AuditEntry>(DashboardHandlers.FilterAuditEntries(
            [Redaction(), Threat(Severity.High)], category: "security", q: null, session: null, source: null));

        var only = Assert.Single(result);
        Assert.Null(only.PolicyCode);
    }

    [Fact]
    public async Task NonRedactionNoneEntry_StillRendersAsNormalRow()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();
        await store.AppendAsync(Threat(Severity.None), CancellationToken.None);

        var html = await GetAsync(host, "/sentinel/api/feed");

        Assert.DoesNotContain("badge redacted", html, StringComparison.Ordinal);
    }
}
