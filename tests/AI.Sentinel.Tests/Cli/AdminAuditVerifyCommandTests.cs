using System.CommandLine;
using System.Globalization;
using System.Text.Json.Nodes;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.Cli;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.AspNetCore;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.AdminAuditTestSupport;

namespace AI.Sentinel.Tests.Cli;

public sealed class AdminAuditVerifyCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sentinel-audit-verify-" + Guid.NewGuid().ToString("N"));
    private readonly ProfileSigningKey _key = NewKey();

    public AdminAuditVerifyCommandTests() => Directory.CreateDirectory(_dir);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* best effort cleanup */ }
    }

    [Fact]
    public async Task Verify_AcceptsACompleteExportAndPrintsCountAndTime()
    {
        var (log, time) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 3, Ct);
        time.Now = T0.AddHours(2);
        var file = await WriteAsync(log, "org-a");

        var (exit, stdout, stderr) = await RunAsync(file, "org-a");

        Assert.True(exit == 0, stderr);
        Assert.Contains("entries=3", stdout, StringComparison.Ordinal);
        Assert.Contains("exported_at=2026-11-23T11:00:00.0000000Z", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_NamesTheFirstBrokenEntry()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 4, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            node["entries"]![2]!["actor"] = "mallory";
            return node;
        });
        var id = JsonNode.Parse(await File.ReadAllTextAsync(file, Ct))!["entries"]![2]!["id"]!.GetValue<string>();

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("hash chain is broken", stderr, StringComparison.Ordinal);
        Assert.Contains(id, stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnExportWithTheLastEntryRemoved()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 3, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            var entries = node["entries"]!.AsArray();
            entries.RemoveAt(entries.Count - 1);
            return node;
        });

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("cut off", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnExportWithTheLastEntryRemovedAndTheHeadRewritten()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 3, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            var entries = node["entries"]!.AsArray();
            entries.RemoveAt(entries.Count - 1);
            node["head"]!["count"] = 2;
            node["head"]!["last_hash"] = entries[^1]!["hash"]!.GetValue<string>();
            return node;
        });

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("signature", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnExportWithTheFirstEntryRemoved()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 3, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            node["entries"]!.AsArray().RemoveAt(0);
            return node;
        });

        var (exit, _, _) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task Verify_RejectsAnExportSignedByAnUnpinnedKey()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var file = await WriteAsync(log, "org-a");

        var (exit, _, stderr) = await RunAsync(file, "org-a", Convert.ToBase64String(NewKey().PublicKey));

        Assert.Equal(2, exit);
        Assert.Contains("not pinned", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnExportForAnotherOrganisation()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var file = await WriteAsync(log, "org-a");

        var (exit, _, stderr) = await RunAsync(file, "org-b");

        Assert.Equal(2, exit);
        Assert.Contains("another organisation", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_AcceptsAnExportThatContainsTheCheckpoint()
    {
        var (log, time) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var first = await WriteAsync(log, "org-a", name: "first.json");
        var checkpoint = await CheckpointOfAsync(first);
        await SeedAsync(log, "org-a", 2, Ct);
        time.Now = T0.AddHours(1);
        var second = await WriteAsync(log, "org-a", name: "second.json");

        var (exit, _, stderr) = await RunAsync(second, "org-a", checkpoint: checkpoint);

        Assert.True(exit == 0, stderr);
    }

    [Fact]
    public async Task Verify_AcceptsTheEmptyCheckpointPrintedForAnEmptyExport()
    {
        var (log, time) = NewLogAt(T0);
        var first = await WriteAsync(log, "org-a", name: "empty.json");
        var (exit0, stdout0, stderr0) = await RunAsync(first, "org-a");
        Assert.True(exit0 == 0, stderr0);
        Assert.Contains("entries=0 last_hash=-", stdout0, StringComparison.Ordinal);

        await SeedAsync(log, "org-a", 2, Ct);
        time.Now = T0.AddHours(1);
        var second = await WriteAsync(log, "org-a", name: "later.json");
        string[] checkpoint = ["--checkpoint-count", "0", "--checkpoint-hash", "-", "--checkpoint-time", AdminAuditHead.FormatTime(T0)];

        Assert.True((await RunAsync(first, "org-a", checkpoint: checkpoint)).Exit == 0);
        var (exit, _, stderr) = await RunAsync(second, "org-a", checkpoint: checkpoint);
        Assert.True(exit == 0, stderr);
    }

    [Fact]
    public async Task Verify_RejectsAnEmptyCheckpointWithAHash()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 1, Ct);
        var file = await WriteAsync(log, "org-a", name: "one.json");
        string[] checkpoint = ["--checkpoint-count", "0", "--checkpoint-hash", "abc", "--checkpoint-time", AdminAuditHead.FormatTime(T0)];

        var (exit, _, stderr) = await RunAsync(file, "org-a", checkpoint: checkpoint);

        Assert.Equal(2, exit);
        Assert.Contains("does not contain the checkpoint", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnOlderCompleteExportAgainstANewerCheckpoint()
    {
        var (log, time) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var older = await WriteAsync(log, "org-a", name: "older.json");
        await SeedAsync(log, "org-a", 2, Ct);
        time.Now = T0.AddHours(1);
        var newer = await WriteAsync(log, "org-a", name: "newer.json");
        var checkpoint = await CheckpointOfAsync(newer);

        var (exit, _, stderr) = await RunAsync(older, "org-a", checkpoint: checkpoint);

        Assert.Equal(2, exit);
        Assert.Contains("older than the checkpoint", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsTheSameEntriesExportedBeforeTheCheckpointTime()
    {
        var (log, time) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 3, Ct);
        time.Now = T0.AddHours(1);
        var earlier = await WriteAsync(log, "org-a", name: "earlier.json");
        time.Now = T0.AddHours(5);
        var later = await WriteAsync(log, "org-a", name: "later.json");
        var checkpoint = await CheckpointOfAsync(later);

        var (exit, _, stderr) = await RunAsync(earlier, "org-a", checkpoint: checkpoint);

        Assert.Equal(2, exit);
        Assert.Contains("older than the checkpoint", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnExportThatDoesNotContainTheCheckpoint()
    {
        var (logA, _) = NewLogAt(T0);
        await SeedAsync(logA, "org-a", 3, Ct);
        var checkpoint = await CheckpointOfAsync(await WriteAsync(logA, "org-a", name: "a.json"));
        var (logB, timeB) = NewLogAt(T0);
        await SeedAsync(logB, "org-a", 3, Ct);
        timeB.Now = T0.AddHours(1);
        var other = await WriteAsync(logB, "org-a", name: "b.json");

        var (exit, _, stderr) = await RunAsync(other, "org-a", checkpoint: checkpoint);

        Assert.Equal(2, exit);
        Assert.Contains("does not contain the checkpoint", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAFileThatIsNotAnExport()
    {
        var file = Path.Combine(_dir, "junk.json");
        await File.WriteAllTextAsync(file, "{ nope", Ct);
        var (exit, _, _) = await RunAsync(file, "org-a");
        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task Verify_ReportsAMissingFileAsAUsageError()
    {
        var (exit, _, stderr) = await RunAsync(Path.Combine(_dir, "missing.json"), "org-a");
        Assert.Equal(1, exit);
        Assert.Contains("Could not read", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsAnIncompleteCheckpoint()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 1, Ct);
        var file = await WriteAsync(log, "org-a");
        var (exit, _, stderr) = await RunAsync(file, "org-a", extra: ["--checkpoint-count", "1"]);
        Assert.Equal(1, exit);
        Assert.Contains("checkpoint", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("AAAA")]
    public async Task Verify_ReportsAPinnedKeyThatIsNotAnEd25519KeyAsAUsageError(string key)
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 1, Ct);
        var file = await WriteAsync(log, "org-a");

        var (exit, _, stderr) = await RunAsync(file, "org-a", key);

        Assert.Equal(1, exit);
        Assert.Contains("--public-key", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsASignatureThatIsNotBase64()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 1, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            node["head"]!["signature"] = "not base64!";
            return node;
        });

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("signature", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("action", "launch")]
    [InlineData("channel", "carrier-pigeon")]
    [InlineData("timestamp", "yesterday")]
    [InlineData("organisation", "org-b")]
    public async Task Verify_RejectsAnEntryWithAnUnknownOrMalformedField(string field, string value)
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            node["entries"]![1]![field] = value;
            return node;
        });

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("not a valid audit log export", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("organisation")]
    [InlineData("exported_at")]
    [InlineData("signature")]
    [InlineData("key_id")]
    public async Task Verify_RejectsAHeadWithAMissingField(string field)
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 1, Ct);
        var file = await WriteAsync(log, "org-a", node =>
        {
            node["head"]!.AsObject().Remove(field);
            return node;
        });

        var (exit, _, stderr) = await RunAsync(file, "org-a");

        Assert.Equal(2, exit);
        Assert.Contains("not a valid audit log export", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_RejectsANegativeCheckpointCount()
    {
        var (log, _) = NewLogAt(T0);
        await SeedAsync(log, "org-a", 2, Ct);
        var file = await WriteAsync(log, "org-a");
        var head = JsonNode.Parse(await File.ReadAllTextAsync(file, Ct))!["head"]!;

        var (exit, _, stderr) = await RunAsync(file, "org-a", extra:
            ["--checkpoint-count", "-1", "--checkpoint-hash", "abc", "--checkpoint-time", head["exported_at"]!.GetValue<string>()]);

        Assert.Equal(2, exit);
        Assert.Contains("does not contain the checkpoint", stderr, StringComparison.Ordinal);
    }

    private (AdminAuditLog Log, SettableTime Time) NewLogAt(DateTimeOffset now)
    {
        var time = new SettableTime(now);
        return (NewLog(_key, time), time);
    }

    private async Task<string> WriteAsync(AdminAuditLog log, string organisation, Func<JsonNode, JsonNode>? tamper = null, string name = "export.json")
    {
        var bytes = await log.ExportAsync(organisation, Ct);
        var text = System.Text.Encoding.UTF8.GetString(bytes);
        if (tamper is not null)
        {
            text = tamper(JsonNode.Parse(text)!).ToJsonString();
        }
        var file = Path.Combine(_dir, name);
        await File.WriteAllTextAsync(file, text, Ct);
        return file;
    }

    private static async Task<string[]> CheckpointOfAsync(string file)
    {
        var head = JsonNode.Parse(await File.ReadAllTextAsync(file, TestContext.Current.CancellationToken))!["head"]!;
        return
        [
            "--checkpoint-count", head["count"]!.GetValue<long>().ToString(CultureInfo.InvariantCulture),
            "--checkpoint-hash", head["last_hash"]!.GetValue<string>(),
            "--checkpoint-time", head["exported_at"]!.GetValue<string>(),
        ];
    }

    private async Task<(int Exit, string Stdout, string Stderr)> RunAsync(
        string file, string organisation, string? publicKey = null, string[]? checkpoint = null, string[]? extra = null)
    {
        var root = new RootCommand { AdminAuditVerifyCommand.Build() };
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        string[] args =
        [
            "audit-verify", file, "--organisation", organisation, "--public-key", publicKey ?? Convert.ToBase64String(_key.PublicKey),
            .. checkpoint ?? [], .. extra ?? [],
        ];
        var exit = await root.Parse(args).InvokeAsync(new InvocationConfiguration { Output = stdout, Error = stderr }, Ct);
        return (exit, stdout.ToString(), stderr.ToString());
    }
}
