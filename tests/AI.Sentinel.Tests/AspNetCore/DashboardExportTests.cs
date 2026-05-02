using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardExportTests
{
    [Fact]
    public async Task Export_FilteredByCategory_ReturnsNdjsonWithOnlyMatchingEntries()
    {
        var host = await BuildHostAsync();
        var store = host.Services.GetRequiredService<IAuditStore>();

        await store.AppendAsync(NewEntry("SEC-01", "security event"), CancellationToken.None);
        await store.AppendAsync(NewEntry("HAL-08", "hallucination event"), CancellationToken.None);
        await store.AppendAsync(NewEntry("AUTHZ-DENY", "authorization deny"), CancellationToken.None);

        var client = host.GetTestClient();
        var resp = await client.GetAsync("/sentinel/api/export.ndjson?filter=security");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/x-ndjson", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal("attachment", resp.Content.Headers.ContentDisposition?.DispositionType);
        var fileName = resp.Content.Headers.ContentDisposition?.FileName?.Trim('"');
        Assert.NotNull(fileName);
        Assert.StartsWith("audit-", fileName!, StringComparison.Ordinal);
        Assert.EndsWith(".ndjson", fileName!, StringComparison.Ordinal);

        var body = await resp.Content.ReadAsStringAsync();
        var lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(lines);  // only the SEC-01 row
        var entry = JsonSerializer.Deserialize<AuditEntry>(lines[0], AuditJsonContext.Default.AuditEntry);
        Assert.Equal("SEC-01", entry?.DetectorId);
    }

    private static async Task<IHost> BuildHostAsync()
    {
        return await new HostBuilder()
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
    }

    private static AuditEntry NewEntry(string detectorId, string summary) =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "deadbeef00000000",
            PreviousHash: null,
            Severity:     Severity.High,
            DetectorId:   detectorId,
            Summary:      summary);
}
