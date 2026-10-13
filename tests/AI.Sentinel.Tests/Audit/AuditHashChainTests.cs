using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditHashChainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);

    private static AuditEntry Unlinked(string id, string summary = "summary", string? sessionId = null) =>
        new(id, T0, Hash: string.Empty, PreviousHash: null, Severity.High, "SEC-01", summary, SessionId: sessionId);

    private static List<AuditEntry> BuildChain(int count)
    {
        var chain = new List<AuditEntry>();
        string? previous = null;
        for (var i = 0; i < count; i++)
        {
            var linked = AuditHashChain.Link(Unlinked($"e{i}", $"summary-{i}"), previous);
            chain.Add(linked);
            previous = linked.Hash;
        }
        return chain;
    }

    private static async IAsyncEnumerable<AuditEntry> AsAsync(IEnumerable<AuditEntry> entries)
    {
        foreach (var e in entries)
        {
            await Task.Yield();
            yield return e;
        }
    }

    [Fact]
    public void Link_SetsPreviousHashAndAHashOverTheEntry()
    {
        var linked = AuditHashChain.Link(Unlinked("e1"), previousHash: "abc");

        Assert.Equal("abc", linked.PreviousHash);
        Assert.Equal(64, linked.Hash.Length);
        Assert.Equal(AuditHashChain.ComputeHash(linked), linked.Hash);
    }

    [Fact]
    public void ComputeHash_IgnoresTheIncomingHashValue()
    {
        var a = Unlinked("e1") with { Hash = "anything" };
        var b = Unlinked("e1") with { Hash = "something else" };

        Assert.Equal(AuditHashChain.ComputeHash(a), AuditHashChain.ComputeHash(b));
    }

    [Fact]
    public void ComputeHash_ChangesWhenPreviousHashChanges()
    {
        Assert.NotEqual(
            AuditHashChain.ComputeHash(Unlinked("e1") with { PreviousHash = "aa" }),
            AuditHashChain.ComputeHash(Unlinked("e1") with { PreviousHash = "ab" }), StringComparer.Ordinal);
    }

    public static TheoryData<string> TamperedFields => new() { "Id", "Timestamp", "Severity", "DetectorId", "Summary", "PolicyCode", "SessionId" };

    [Theory]
    [MemberData(nameof(TamperedFields))]
    public void ComputeHash_CoversEveryRecordedField(string field)
    {
        var original = AuditHashChain.Link(Unlinked("e1", sessionId: "s1") with { PolicyCode = "policy_denied" }, null);
        var tampered = field switch
        {
            "Id" => original with { Id = "e2" },
            "Timestamp" => original with { Timestamp = original.Timestamp.AddTicks(1) },
            "Severity" => original with { Severity = Severity.Low },
            "DetectorId" => original with { DetectorId = "SEC-02" },
            "Summary" => original with { Summary = "edited" },
            "PolicyCode" => original with { PolicyCode = null },
            "SessionId" => original with { SessionId = "s2" },
            _ => throw new ArgumentOutOfRangeException(nameof(field)),
        };

        Assert.NotEqual(original.Hash, AuditHashChain.ComputeHash(tampered), StringComparer.Ordinal);
    }

    [Fact]
    public void ComputeHash_DoesNotConfuseFieldBoundaries()
    {
        // Naive concatenation would hash "ab" + "c" and "a" + "bc" identically.
        var a = Unlinked("e1") with { DetectorId = "ab", Summary = "c" };
        var b = Unlinked("e1") with { DetectorId = "a", Summary = "bc" };

        Assert.NotEqual(AuditHashChain.ComputeHash(a), AuditHashChain.ComputeHash(b), StringComparer.Ordinal);
    }

    [Fact]
    public void ComputeHash_DistinguishesNullFromEmpty()
    {
        Assert.NotEqual(
            AuditHashChain.ComputeHash(Unlinked("e1") with { SessionId = null }),
            AuditHashChain.ComputeHash(Unlinked("e1") with { SessionId = "" }), StringComparer.Ordinal);
    }

    [Fact]
    public async Task VerifyAsync_IntactChain_IsIntactFromGenesis()
    {
        var result = await AuditHashChain.VerifyAsync(AsAsync(BuildChain(5)), CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(5, result.EntriesChecked);
        Assert.Null(result.FirstBrokenEntryId);
        Assert.Null(result.AnchorHash);
    }

    [Fact]
    public async Task VerifyAsync_EmptyStore_IsIntact()
    {
        var result = await AuditHashChain.VerifyAsync(AsAsync([]), CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(0, result.EntriesChecked);
    }

    [Fact]
    public async Task VerifyAsync_EditedEntry_ReportsThatEntry()
    {
        var chain = BuildChain(5);
        chain[2] = chain[2] with { Summary = "rewritten after the fact" };

        var result = await AuditHashChain.VerifyAsync(AsAsync(chain), CancellationToken.None);

        Assert.False(result.IsIntact);
        Assert.Equal("e2", result.FirstBrokenEntryId);
    }

    [Fact]
    public async Task VerifyAsync_DeletedEntry_ReportsTheEntryAfterTheGap()
    {
        var chain = BuildChain(5);
        chain.RemoveAt(2);

        var result = await AuditHashChain.VerifyAsync(AsAsync(chain), CancellationToken.None);

        Assert.False(result.IsIntact);
        Assert.Equal("e3", result.FirstBrokenEntryId);
    }

    [Fact]
    public async Task VerifyAsync_RehashedEditStillBreaksTheNextLink()
    {
        // An attacker who edits an entry and recomputes its own hash still breaks the successor.
        var chain = BuildChain(5);
        chain[2] = AuditHashChain.Link(chain[2] with { Summary = "rewritten" }, chain[2].PreviousHash);

        var result = await AuditHashChain.VerifyAsync(AsAsync(chain), CancellationToken.None);

        Assert.False(result.IsIntact);
        Assert.Equal("e3", result.FirstBrokenEntryId);
    }

    [Fact]
    public async Task VerifyAsync_HeadRemovedByRetention_IsIntactAndReportsTheAnchor()
    {
        var chain = BuildChain(5);
        var anchor = chain[1].Hash;
        chain.RemoveRange(0, 2);

        var result = await AuditHashChain.VerifyAsync(AsAsync(chain), CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(3, result.EntriesChecked);
        Assert.Equal(anchor, result.AnchorHash);
    }
}
