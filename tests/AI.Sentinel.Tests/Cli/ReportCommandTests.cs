using System.CommandLine;
using System.Security.Cryptography;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Cli;
using AI.Sentinel.Cli.Report;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

public sealed class ReportCommandTests : IDisposable
{
    private const string Marker = "SUMMARY-MARKER-7f3a";
    private static readonly DateTimeOffset Now = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-report-" + Guid.NewGuid().ToString("N"));

    public ReportCommandTests() => Directory.CreateDirectory(_dir);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    [Fact]
    public async Task Report_Markdown_HasAllSections()
    {
        var db = await SeedAsync(DefaultEntries());

        var (exit, stdout, _) = await RunAsync("--db", db);

        Assert.Equal(0, exit);
        Assert.Contains(ComplianceReport.DisclaimerText, stdout, StringComparison.Ordinal);
        Assert.Contains(db, stdout, StringComparison.Ordinal);
        foreach (var heading in new[] { "## Art. 12", "## Art. 14", "## Art. 10", "## Art. 50", "## Art. 5 ", "## Art. 15" })
        {
            Assert.Contains(heading, stdout, StringComparison.Ordinal);
        }
        Assert.Contains("SEC-01", stdout, StringComparison.Ordinal);
        Assert.Contains("CMP-01", stdout, StringComparison.Ordinal);
        Assert.Contains("EMAIL", stdout, StringComparison.Ordinal);
        Assert.Contains("APPROVED", stdout, StringComparison.Ordinal);
        Assert.Contains("intact", stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(ComplianceReport.Art5NoDetectionsNote, stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Report_Html_SelfContained_NoExternalRefs()
    {
        var entries = DefaultEntries();
        entries.Add(Entry(Severity.Low, "X-<i>&", "x") with { Source = "tool<script>" });
        var db = await SeedAsync(entries);

        var (exit, html, _) = await RunAsync("--db", db, "--format", "html");

        Assert.Equal(0, exit);
        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("<style>", html, StringComparison.Ordinal);
        Assert.Contains(ComplianceReport.DisclaimerText, html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("X-&lt;i&gt;&amp;", html, StringComparison.Ordinal);
        Assert.Contains("tool&lt;script&gt;", html, StringComparison.Ordinal);
        foreach (var heading in new[] { "Art. 12", "Art. 14", "Art. 10", "Art. 50", "Art. 5 ", "Art. 15" })
        {
            Assert.Contains(heading, html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Report_Json_Schema1_RoundTrips()
    {
        var db = await SeedAsync(DefaultEntries());

        var (exit, json, _) = await RunAsync("--db", db, "--format", "json");

        Assert.Equal(0, exit);
        using (var doc = JsonDocument.Parse(json))
        {
            var root = doc.RootElement;
            Assert.Equal(1, root.GetProperty("schema").GetInt32());
            Assert.Equal(ComplianceReport.DisclaimerText, root.GetProperty("disclaimer").GetString());
            Assert.Equal(db, root.GetProperty("auditFilePath").GetString());
            Assert.True(root.GetProperty("art12").GetProperty("chainIntact").GetBoolean());
            Assert.Equal("High", root.GetProperty("art15").GetProperty("detections")[0].GetProperty("severity").GetString());
        }

        var report = JsonSerializer.Deserialize(json, ComplianceReportJsonContext.Default.ComplianceReport);
        Assert.NotNull(report);
        Assert.Equal(1, report.Schema);
        Assert.Equal(ComplianceReport.DisclaimerText, report.Disclaimer);
        Assert.Equal(6, report.Art12.EntriesInPeriod);
        Assert.Equal(1, report.Art14.AuthorizationDenials);
        Assert.Equal(1, report.Art14.ApprovalRequestsByOutcome["APPROVED"]);
        Assert.Equal(2, report.Art10.RedactionsByType["EMAIL"]);
        Assert.Equal(1, report.Art50.DisclosedSessions);
        Assert.True(report.Art5.AnyDetections);
        Assert.Equal("CMP-01", Assert.Single(report.Art5.Detections).DetectorId);
        Assert.Equal(new ComplianceReport.DetectionCount("SEC-01", Severity.High, 1), Assert.Single(report.Art15.Detections));
        Assert.Equal(Now, report.GeneratedAt);
    }

    [Fact]
    public async Task BrokenChain_ExitCode2_StillWritesReport()
    {
        var entries = DefaultEntries();
        var db = await SeedAsync(entries);
        await ExecuteAsync(db, "UPDATE audit_entries SET summary = 'edited' WHERE id = $id", entries[1].Id);

        var (exit, stdout, stderr) = await RunAsync("--db", db);

        Assert.Equal(2, exit);
        Assert.Contains("## Art. 15", stdout, StringComparison.Ordinal);
        Assert.Contains("broken", stdout, StringComparison.Ordinal);
        Assert.Contains(entries[1].Id, stdout, StringComparison.Ordinal);
        Assert.Contains(entries[1].Id, stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingDb_ExitCode1_FileNotCreated()
    {
        var db = Path.Combine(_dir, "sub", "missing.db");

        var (exit, stdout, stderr) = await RunAsync("--db", db);

        Assert.Equal(1, exit);
        Assert.Equal(string.Empty, stdout);
        Assert.Contains(db, stderr, StringComparison.Ordinal);
        Assert.False(File.Exists(db));
        Assert.False(Directory.Exists(Path.Combine(_dir, "sub")));
    }

    [Fact]
    public async Task CorruptDb_ExitCode1()
    {
        var db = Path.Combine(_dir, "corrupt.db");
        await File.WriteAllTextAsync(db, "this is not a sqlite database, just some text padding it out a bit", Ct);

        var (exit, stdout, stderr) = await RunAsync("--db", db);

        Assert.Equal(1, exit);
        Assert.Equal(string.Empty, stdout);
        Assert.Contains(db, stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(" at ", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmptySqliteFileWithoutSchema_ExitCode1_Unchanged()
    {
        var db = Path.Combine(_dir, "blank.db");
        await File.WriteAllBytesAsync(db, [], Ct);

        var (exit, _, stderr) = await RunAsync("--db", db);

        Assert.Equal(1, exit);
        Assert.Contains(db, stderr, StringComparison.Ordinal);
        Assert.Equal(0, new FileInfo(db).Length);
    }

    [Fact]
    public async Task EmptyDb_Exit0_NoEntriesSections()
    {
        var db = await SeedAsync([]);

        foreach (var format in new[] { "md", "html", "json" })
        {
            var (exit, output, _) = await RunAsync("--db", db, "--format", format);

            Assert.Equal(0, exit);
            if (string.Equals(format, "json", StringComparison.Ordinal))
            {
                var report = JsonSerializer.Deserialize(output, ComplianceReportJsonContext.Default.ComplianceReport)!;
                Assert.Equal(0, report.Art12.EntriesInPeriod);
                Assert.Equal(ComplianceReport.Art5NoDetectionsNote, report.Art5.Note);
                continue;
            }

            Assert.Contains("No entries in this period", output, StringComparison.Ordinal);
            Assert.Contains("No approval decisions recorded", output, StringComparison.Ordinal);
            Assert.Contains("No redactions recorded", output, StringComparison.Ordinal);
            Assert.Contains("No disclosures recorded", output, StringComparison.Ordinal);
            Assert.Contains("No detections recorded", output, StringComparison.Ordinal);
            Assert.Contains(ComplianceReport.Art5NoDetectionsNote, output, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task OutputOption_WritesFile()
    {
        var db = await SeedAsync(DefaultEntries());
        var output = Path.Combine(_dir, "report.html");

        var (exit, stdout, _) = await RunAsync("--db", db, "--format", "html", "--output", output);

        Assert.Equal(0, exit);
        Assert.Equal(string.Empty, stdout);
        var html = await File.ReadAllTextAsync(output, Ct);
        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains(ComplianceReport.DisclaimerText, html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("md")]
    [InlineData("html")]
    [InlineData("json")]
    public async Task Output_ContainsNoSummaryText(string format)
    {
        var db = await SeedAsync(DefaultEntries());

        var (exit, output, _) = await RunAsync("--db", db, "--format", format);

        Assert.Equal(0, exit);
        Assert.DoesNotContain(Marker, output, StringComparison.Ordinal);
        Assert.DoesNotContain("session-", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Report_DoesNotModifyTheAuditFile()
    {
        var db = await SeedAsync(DefaultEntries());
        var before = await HashAsync(db);

        var (exit, _, _) = await RunAsync("--db", db);

        Assert.Equal(0, exit);
        Assert.Equal(before, await HashAsync(db));
    }

    [Fact]
    public async Task DefaultPeriod_IsTheLast30Days()
    {
        var db = await SeedAsync([
            Entry(Severity.Low, "SEC-01", "recent", at: Now.AddDays(-29)),
            Entry(Severity.Low, "SEC-01", "old", at: Now.AddDays(-31)),
        ]);

        var report = await RunJsonAsync("--db", db);

        Assert.Equal(Now.AddDays(-30), report.From);
        Assert.Equal(Now, report.To);
        Assert.Equal(1, report.Art12.EntriesInPeriod);
    }

    [Fact]
    public async Task DateOnlyOptions_CoverWholeUtcDays()
    {
        var db = await SeedAsync([
            Entry(Severity.Low, "SEC-01", "before", at: new DateTimeOffset(2026, 10, 9, 23, 59, 59, TimeSpan.Zero)),
            Entry(Severity.Low, "SEC-01", "start", at: new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero)),
            Entry(Severity.Low, "SEC-01", "end", at: new DateTimeOffset(2026, 10, 11, 23, 59, 59, TimeSpan.Zero)),
            Entry(Severity.Low, "SEC-01", "after", at: new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero)),
        ]);

        var report = await RunJsonAsync("--db", db, "--from", "2026-10-10", "--to", "2026-10-11");

        Assert.Equal(new DateTimeOffset(2026, 10, 10, 0, 0, 0, TimeSpan.Zero), report.From);
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero).AddTicks(-1), report.To);
        Assert.Equal(2, report.Art12.EntriesInPeriod);
    }

    [Fact]
    public async Task TimestampOptions_AreUsedAsGiven()
    {
        var db = await SeedAsync([
            Entry(Severity.Low, "SEC-01", "in", at: new DateTimeOffset(2026, 10, 10, 10, 30, 0, TimeSpan.Zero)),
            Entry(Severity.Low, "SEC-01", "out", at: new DateTimeOffset(2026, 10, 10, 9, 30, 0, TimeSpan.Zero)),
        ]);

        var report = await RunJsonAsync("--db", db, "--from", "2026-10-10T12:00:00+02:00", "--to", "2026-10-10T11:00:00Z");

        Assert.Equal(new DateTimeOffset(2026, 10, 10, 10, 0, 0, TimeSpan.Zero), report.From.ToUniversalTime());
        Assert.Equal(1, report.Art12.EntriesInPeriod);
    }

    [Fact]
    public async Task FromAfterTo_ExitCode1()
    {
        var db = await SeedAsync([]);

        var (exit, stdout, stderr) = await RunAsync("--db", db, "--from", "2026-10-12", "--to", "2026-10-11");

        Assert.Equal(1, exit);
        Assert.Equal(string.Empty, stdout);
        Assert.Contains("--from", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--from", "yesterday")]
    [InlineData("--to", "2026-13-01")]
    [InlineData("--to", "17/10/2026")]
    public async Task InvalidDate_ExitCode1(string option, string value)
    {
        var db = await SeedAsync([]);

        var (exit, stdout, stderr) = await RunAsync("--db", db, option, value);

        Assert.Equal(1, exit);
        Assert.Equal(string.Empty, stdout);
        Assert.Contains(option, stderr, StringComparison.Ordinal);
        Assert.Contains(value, stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidFormat_IsAParseError()
    {
        var db = await SeedAsync([]);

        var (exit, _, stderr) = await RunAsync("--db", db, "--format", "pdf");

        Assert.NotEqual(0, exit);
        Assert.Contains("pdf", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoDbAndDefaultPathNotRooted_ExitCode1()
    {
        var root = new RootCommand { ReportCommand.Build(() => "audit.db", new FixedTime(Now)) };
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await root.Parse(["report"]).InvokeAsync(
            new InvocationConfiguration { Output = stdout, Error = stderr }, Ct);

        Assert.Equal(1, exit);
        Assert.Contains("--db", stderr.ToString(), StringComparison.Ordinal);
    }

    private List<AuditEntry> DefaultEntries() =>
    [
        Entry(Severity.High, "SEC-01", "prompt injection " + Marker, session: "session-a"),
        Entry(Severity.High, "CMP-01", "social scoring " + Marker, session: "session-a"),
        Entry(Severity.None, "REDACTION", "Redacted 2 EMAIL", policyCode: "REDACTED", session: "session-b"),
        Entry(Severity.None, AuditEntryKinds.TransparencyDetectorId, "Disclosed " + Marker, policyCode: AuditEntryKinds.DisclosedPolicyCode, session: "session-c"),
        Entry(Severity.None, AuditEntryKinds.ApprovalDetectorId, "Approved tool " + Marker + ", request req-1", policyCode: AuditEntryKinds.ApprovedPolicyCode),
        Entry(Severity.High, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, "denied " + Marker, policyCode: "policy-x"),
    ];

    private static AuditEntry Entry(
        Severity severity, string detectorId, string summary, string? policyCode = null, string? session = null, DateTimeOffset? at = null) =>
        new(Guid.NewGuid().ToString("N"), at ?? Now.AddDays(-1), string.Empty, null, severity, detectorId, summary)
        {
            PolicyCode = policyCode,
            SessionId = session,
        };

    private async Task<string> SeedAsync(List<AuditEntry> entries)
    {
        var db = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        foreach (var entry in entries)
        {
            await store.AppendAsync(entry, Ct);
        }
        return db;
    }

    private static async Task ExecuteAsync(string db, string sql, string id)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = db, Pooling = false }.ToString());
        await connection.OpenAsync(Ct);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$id", id);
        Assert.Equal(1, await cmd.ExecuteNonQueryAsync(Ct));
    }

    private static async Task<string> HashAsync(string path) =>
        Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path, Ct)));

    private async Task<(int Exit, string Stdout, string Stderr)> RunAsync(params string[] args)
    {
        var root = new RootCommand { ReportCommand.Build(() => Path.Combine(_dir, "default.db"), new FixedTime(Now)) };
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await root.Parse(["report", .. args]).InvokeAsync(
            new InvocationConfiguration { Output = stdout, Error = stderr }, Ct);

        return (exit, stdout.ToString(), stderr.ToString());
    }

    private async Task<ComplianceReport> RunJsonAsync(params string[] args)
    {
        var (exit, json, stderr) = await RunAsync([.. args, "--format", "json"]);
        Assert.True(exit == 0, stderr);
        return JsonSerializer.Deserialize(json, ComplianceReportJsonContext.Default.ComplianceReport)!;
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
