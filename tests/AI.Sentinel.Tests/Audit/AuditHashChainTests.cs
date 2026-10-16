using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditHashChainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);

    private static AuditEntry Unlinked(string id, string summary = "summary", string? sessionId = null) =>
        new(id, T0, Hash: string.Empty, PreviousHash: null, Severity.High, "SEC-01", summary) { SessionId = sessionId };

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

    public static TheoryData<string> TamperedFields => new() { "Id", "Timestamp", "Severity", "DetectorId", "Summary", "PolicyCode", "SessionId", "Source" };

    [Theory]
    [MemberData(nameof(TamperedFields))]
    public void ComputeHash_CoversEveryRecordedField(string field)
    {
        var original = AuditHashChain.Link(Unlinked("e1", sessionId: "s1") with { PolicyCode = "policy_denied", Source = AuditSources.ClaudeCode }, null);
        var tampered = field switch
        {
            "Id" => original with { Id = "e2" },
            "Timestamp" => original with { Timestamp = original.Timestamp.AddTicks(1) },
            "Severity" => original with { Severity = Severity.Low },
            "DetectorId" => original with { DetectorId = "SEC-02" },
            "Summary" => original with { Summary = "edited" },
            "PolicyCode" => original with { PolicyCode = null },
            "SessionId" => original with { SessionId = "s2" },
            "Source" => original with { Source = "mcp" },
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
    public void ComputeHash_DistinguishesNullFromEmptySource()
    {
        Assert.NotEqual(
            AuditHashChain.ComputeHash(Unlinked("e1") with { Source = null }),
            AuditHashChain.ComputeHash(Unlinked("e1") with { Source = "" }), StringComparer.Ordinal);
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

    // Golden values for the stored hash format. They were computed from the 3.0 encoding, both by
    // ComputeHash and independently from the byte layout it documents. If one of these fails, the
    // format changed and every hash already in a store would stop verifying: restore the format
    // instead of updating the constant. See the remarks on AuditHashChain.ComputeHash.
    private const string GoldenHash1 = "53f54bb2b0837aa8f0b6e21e3ae6c591d4c2802ba2c99a13ed1c779dafde37aa";
    private const string GoldenHash2 = "d296074b184820ae2b11d61013bb4f3e6511171c1b99713285b20943cad1cd63";
    private const string GoldenHash3 = "3831dcfc24bf083b4c5bf871b399a7039b528ca037d3eb29241e5ede7123c323";

    private static AuditEntry[] GoldenChain() =>
    [
        // Every optional field null.
        new("golden-1", T0, GoldenHash1, PreviousHash: null, Severity.High, "SEC-01", "summary"),

        // Every optional field set.
        new("golden-2", T0.AddSeconds(1), GoldenHash2, PreviousHash: GoldenHash1, Severity.Critical, "AUTHZ-DENY", "denied")
        {
            PolicyCode = "policy_denied",
            SessionId = "sess-1",
            Source = AuditSources.ClaudeCode,
        },

        // Lowest severity, non-ASCII text, and an empty string next to nulls.
        new("golden-3", T0.AddSeconds(2), GoldenHash3, PreviousHash: GoldenHash2, Severity.None, "OPS-01", "naïve — ü")
        {
            SessionId = string.Empty,
        },
    ];

    [Fact]
    public void ComputeHash_MatchesThePinnedFormat()
    {
        var chain = GoldenChain();

        Assert.Equal(GoldenHash1, AuditHashChain.ComputeHash(chain[0]));
        Assert.Equal(GoldenHash2, AuditHashChain.ComputeHash(chain[1]));
        Assert.Equal(GoldenHash3, AuditHashChain.ComputeHash(chain[2]));
    }

    [Fact]
    public void Link_ProducesThePinnedHashes()
    {
        var chain = GoldenChain();
        string? previous = null;
        foreach (var stored in chain)
        {
            var relinked = AuditHashChain.Link(stored with { Hash = string.Empty, PreviousHash = null }, previous);
            Assert.Equal(stored, relinked);
            previous = relinked.Hash;
        }
    }

    [Fact]
    public async Task VerifyAsync_ChainWrittenInThePinnedFormat_IsIntact()
    {
        var result = await AuditHashChain.VerifyAsync(AsAsync(GoldenChain()), CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(3, result.EntriesChecked);
        Assert.Null(result.AnchorHash);
    }

    [Fact]
    public void Severity_ValuesArePinned()
    {
        // Hashed and stored as integers; see the remarks on Severity.
        Assert.Equal(0, (int)Severity.None);
        Assert.Equal(1, (int)Severity.Low);
        Assert.Equal(2, (int)Severity.Medium);
        Assert.Equal(3, (int)Severity.High);
        Assert.Equal(4, (int)Severity.Critical);
        Assert.Equal(5, Enum.GetValues<Severity>().Length);
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
