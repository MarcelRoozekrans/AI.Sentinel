using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class NdjsonFileAuditForwarderTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.ndjson");

    public void Dispose()
    {
        try
        {
            File.Delete(_tempPath);
        }
        catch (IOException)
        {
            // best effort cleanup
        }
        catch (UnauthorizedAccessException)
        {
            // best effort cleanup
        }
        GC.SuppressFinalize(this);
    }

    private static AuditEntry MakeEntry(string id, string summary = "test") =>
        new(id, DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", summary);

    [Fact]
    public async Task SendAsync_AppendsLineToFile()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("e1", parsed.RootElement.GetProperty("Id").GetString());
    }

    [Fact]
    public async Task SendAsync_MultipleEntries_OneLinePerEntry()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1"), MakeEntry("e2"), MakeEntry("e3")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(3, lines.Length);
    }

    [Fact]
    public async Task SendAsync_NewlinesInSummary_EscapedNotBreakingFormat()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1", "line1\nline2\nline3")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("line1\nline2\nline3", parsed.RootElement.GetProperty("Summary").GetString());
    }

    [Fact]
    public async Task SendAsync_AppendMode_PreservesPriorContent()
    {
        File.WriteAllText(_tempPath, "{\"existing\":\"line\"}\n");

        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(2, lines.Length);
        Assert.Contains("existing", lines[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_AfterDispose_DoesNotThrow()
    {
        var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath });
        await f.DisposeAsync();
        // After dispose, writing should NOT throw — the IAuditForwarder contract says MUST NOT throw.
        // The new try/catch in SendAsync swallows the ObjectDisposedException.
        await f.SendAsync([MakeEntry("e1")], default);
    }
}
