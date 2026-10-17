using System.Collections;
using System.Reflection;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Cli.Report;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

public class ComplianceReportBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset From = Now.AddDays(-30);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static AuditEntry Entry(
        Severity severity, string detectorId, string summary, string? policyCode = null,
        string? session = null, string? source = null, DateTimeOffset? at = null) =>
        new(Guid.NewGuid().ToString("N"), at ?? Now.AddDays(-1), string.Empty, null, severity, detectorId, summary)
        {
            PolicyCode = policyCode,
            SessionId = session,
            Source = source,
        };

    private static async Task<ComplianceReport> BuildAsync(RingBufferAuditStore store) =>
        await ComplianceReportBuilder.BuildAsync(store, From, Now, "/data/audit.db", new FixedTime(Now), Ct);

    private static async Task Seed(RingBufferAuditStore store, params AuditEntry[] entries)
    {
        foreach (var e in entries)
        {
            await store.AppendAsync(e, Ct);
        }
    }

    [Fact]
    public async Task Art12_ChainIntact_CountsBySource()
    {
        using var store = new RingBufferAuditStore();
        await Seed(store,
            Entry(Severity.Low, "SEC-01", "a"),
            Entry(Severity.Low, "SEC-01", "b", source: AuditSources.Mcp),
            Entry(Severity.Low, "SEC-01", "c", source: AuditSources.Mcp),
            Entry(Severity.Low, "SEC-01", "old", at: From.AddDays(-5)));

        var report = await BuildAsync(store);

        Assert.Equal(1, report.Schema);
        Assert.True(report.Art12.ChainIntact);
        Assert.Equal(4, report.Art12.EntriesChecked);
        Assert.Null(report.Art12.FirstBrokenEntryId);
        Assert.Equal(3, report.Art12.EntriesInPeriod);
        Assert.Equal(1, report.Art12.EntriesBySource["in-process"]);
        Assert.Equal(2, report.Art12.EntriesBySource["mcp"]);
        Assert.Equal("/data/audit.db", report.AuditFilePath);
        Assert.Equal(Now, report.GeneratedAt);
        Assert.Equal(
            "This report summarises what AI.Sentinel recorded in its audit log. It is evidence to support an EU AI Act assessment, not a statement of compliance.",
            report.Disclaimer);
        Assert.Contains("trimmed", report.Art12.ChainNote, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Art12_BrokenChain_FirstBrokenId()
    {
        using var good = new RingBufferAuditStore();
        var first = await good.AppendAsync(Entry(Severity.Low, "SEC-01", "a"), Ct);
        var second = await good.AppendAsync(Entry(Severity.Low, "SEC-01", "b"), Ct);
        var tampered = second with { Summary = "edited" };
        var store = new TamperedStore(first, tampered);

        var report = await ComplianceReportBuilder.BuildAsync(store, From, Now, "x.db", new FixedTime(Now), Ct);

        Assert.False(report.Art12.ChainIntact);
        Assert.Equal(second.Id, report.Art12.FirstBrokenEntryId);
        Assert.Equal(1, report.Art12.EntriesChecked);
    }

    [Fact]
    public async Task Art14_DenialsAndApprovalOutcomes_DistinctRequests()
    {
        using var store = new RingBufferAuditStore();
        AuditEntry Approval(string code, string outcome, string id) =>
            Entry(Severity.None, AuditEntryKinds.ApprovalDetectorId, $"{outcome}: policy p, tool t, request {id}", code);
        await Seed(store,
            Entry(Severity.High, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, "denied", "policy-x"),
            Entry(Severity.High, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, "denied", "policy-x"),
            Approval(AuditEntryKinds.ApprovedPolicyCode, "Approved", "r1"),
            Approval(AuditEntryKinds.ApprovedPolicyCode, "Approved", "r1"),
            Approval(AuditEntryKinds.ApprovedPolicyCode, "Approved", "r2"),
            Approval(AuditEntryKinds.DeniedPolicyCode, "Denied", "r3"),
            Approval(AuditEntryKinds.ExpiredPolicyCode, "Expired", "unknown"),
            Approval(AuditEntryKinds.ExpiredPolicyCode, "Expired", "unknown"),
            Approval(AuditEntryKinds.TimedOutPolicyCode, "Timed out", "r4"));

        var report = await BuildAsync(store);

        Assert.Equal(2, report.Art14.AuthorizationDenials);
        var o = report.Art14.ApprovalRequestsByOutcome;
        Assert.Equal(2, o[AuditEntryKinds.ApprovedPolicyCode]);
        Assert.Equal(1, o[AuditEntryKinds.DeniedPolicyCode]);
        Assert.Equal(2, o[AuditEntryKinds.ExpiredPolicyCode]);
        Assert.Equal(1, o[AuditEntryKinds.TimedOutPolicyCode]);
        Assert.Empty(report.Art15.Detections);
    }

    [Fact]
    public async Task Art14_ApprovalHolds_AreNotCountedAsDenials()
    {
        // The hooks, the MCP proxy and the in-process guard write each approval hold as AUTHZ-DENY with the
        // approval_required code. A request held three times and then approved is not three denials.
        using var store = new RingBufferAuditStore();
        AuditEntry Deny(string code) =>
            AuditEntryAuthorizationExtensions.AuthorizationDeny(
                new AgentId("user"), new AgentId("assistant"), SessionId.New(), "alice",
                new HashSet<string>(StringComparer.Ordinal), "delete_database", "p", "held", code)
            with { Timestamp = Now.AddDays(-1) };
        await Seed(store,
            Deny(SentinelDenyCodes.ApprovalRequired),
            Deny(SentinelDenyCodes.ApprovalRequired),
            Deny(SentinelDenyCodes.ApprovalRequired),
            Deny(SentinelDenyCodes.PolicyDenied));

        var report = await BuildAsync(store);

        Assert.Equal(1, report.Art14.AuthorizationDenials);
        Assert.Equal(3, report.Art14.ApprovalHolds);
    }

    [Fact]
    public async Task Art10_RedactionCountsPerType_AndFallbacks()
    {
        using var store = new RingBufferAuditStore();
        await Seed(store,
            AuditEntryRedactionExtensions.Redaction("PRIV-01", new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 2, ["IBAN"] = 1 }, "s1"),
            AuditEntryRedactionExtensions.Redaction("PRIV-01", new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 3 }, "s2"),
            Entry(Severity.High, "PRIV-01", "Found secret; not redacted"));

        var report = await BuildAsync(store);

        Assert.Equal(5, report.Art10.RedactionsByType["EMAIL"]);
        Assert.Equal(1, report.Art10.RedactionsByType["IBAN"]);
        Assert.Equal(1, report.Art10.FallbackEntries);
        Assert.DoesNotContain(report.Art15.Detections, d => d.Severity == Severity.None);
    }

    [Fact]
    public async Task Art50_DistinctDisclosedSessions()
    {
        using var store = new RingBufferAuditStore();
        AuditEntry Disclosed(string s) =>
            Entry(Severity.None, AuditEntryKinds.TransparencyDetectorId, "Disclosed: machine-readable mark", AuditEntryKinds.DisclosedPolicyCode, s);
        await Seed(store, Disclosed("s1"), Disclosed("s1"), Disclosed("s2"));

        var report = await BuildAsync(store);

        Assert.Equal(2, report.Art50.DisclosedSessions);
    }

    [Fact]
    public async Task Art50_DisclosureWithoutSession_CountsOncePerEntry()
    {
        using var store = new RingBufferAuditStore();
        AuditEntry Disclosed(string? s) =>
            Entry(Severity.None, AuditEntryKinds.TransparencyDetectorId, "Disclosed: machine-readable mark", AuditEntryKinds.DisclosedPolicyCode, s);
        await Seed(store, Disclosed(null), Disclosed(null), Disclosed("s1"));

        var report = await BuildAsync(store);

        Assert.Equal(3, report.Art50.DisclosedSessions);
    }

    [Fact]
    public async Task Art5_CmpDetectionsSeparatedFromArt15()
    {
        using var store = new RingBufferAuditStore();
        await Seed(store,
            Entry(Severity.High, "CMP-01", "x"),
            Entry(Severity.High, "CMP-01", "x"),
            Entry(Severity.Medium, "CMP-02", "x"),
            Entry(Severity.Low, "SEC-01", "x"),
            Entry(Severity.Low, "SEC-01", "x"),
            Entry(Severity.High, "SEC-01", "x"),
            Entry(Severity.Low, "HAL-01", "x"));

        var report = await BuildAsync(store);

        Assert.True(report.Art5.AnyDetections);
        Assert.Null(report.Art5.Note);
        Assert.Equal(2, report.Art5.Detections.Count);
        Assert.Contains(report.Art5.Detections, d => d is { DetectorId: "CMP-01", Severity: Severity.High, Count: 2 });
        Assert.DoesNotContain(report.Art15.Detections, d => d.DetectorId.StartsWith("CMP-", StringComparison.Ordinal));
        Assert.Contains(report.Art15.Detections, d => d is { DetectorId: "SEC-01", Severity: Severity.Low, Count: 2 });
        Assert.Equal("SEC-01", report.Art15.TopDetectors[0].DetectorId);
        Assert.Equal(3, report.Art15.TopDetectors[0].Count);
        Assert.Equal(2, report.Art15.TopDetectors.Count);
    }

    [Fact]
    public async Task Art15_TopDetectors_AreCappedAtFive()
    {
        using var store = new RingBufferAuditStore();
        for (var i = 0; i < 7; i++)
        {
            await Seed(store, Entry(Severity.Low, $"SEC-0{i}", "x"));
        }

        var report = await BuildAsync(store);

        Assert.Equal(5, report.Art15.TopDetectors.Count);
    }

    [Fact]
    public async Task EmptyPeriod_AllSectionsEmpty()
    {
        using var store = new RingBufferAuditStore();

        var report = await BuildAsync(store);

        Assert.True(report.Art12.ChainIntact);
        Assert.Equal(0, report.Art12.EntriesChecked);
        Assert.Equal(0, report.Art12.EntriesInPeriod);
        Assert.Empty(report.Art12.EntriesBySource);
        Assert.Equal(0, report.Art14.AuthorizationDenials);
        Assert.Equal(0, report.Art14.ApprovalHolds);
        Assert.Empty(report.Art14.ApprovalRequestsByOutcome);
        Assert.Empty(report.Art10.RedactionsByType);
        Assert.Equal(0, report.Art10.FallbackEntries);
        Assert.Equal(0, report.Art50.DisclosedSessions);
        Assert.False(report.Art5.AnyDetections);
        Assert.Empty(report.Art5.Detections);
        Assert.Equal(
            "No Art. 5 detections were recorded. The Art. 5 detectors are opt-in; this means nothing was detected while they were enabled, not that no prohibited-practice request occurred.",
            report.Art5.Note);
        Assert.Empty(report.Art15.Detections);
        Assert.Empty(report.Art15.TopDetectors);
    }

    [Fact]
    public async Task Model_ContainsNoSummaryOrSessionText()
    {
        using var store = new RingBufferAuditStore();
        await Seed(store,
            Entry(Severity.High, "SEC-01", "SECRET-SUMMARY-TEXT", session: "SESSION-ABC"),
            Entry(Severity.High, "SEC-02", "SECRET-SUMMARY-TEXT; not redacted", session: "SESSION-ABC"),
            Entry(Severity.High, AuditEntryAuthorizationExtensions.AuthorizationDenyDetectorId, "SECRET-SUMMARY-TEXT", "policy-x", "SESSION-ABC"),
            AuditEntryRedactionExtensions.Redaction("PRIV-01", new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 }, "SESSION-ABC"),
            Entry(Severity.High, "CMP-01", "SECRET-SUMMARY-TEXT", session: "SESSION-ABC"),
            Entry(Severity.None, AuditEntryKinds.TransparencyDetectorId, "Disclosed: SECRET-SUMMARY-TEXT", AuditEntryKinds.DisclosedPolicyCode, "SESSION-ABC"),
            Entry(Severity.None, AuditEntryKinds.ApprovalDetectorId, "Approved: policy SECRET-SUMMARY-TEXT, tool t, request REQ-SECRET-1", AuditEntryKinds.ApprovedPolicyCode, "SESSION-ABC"));

        var report = await BuildAsync(store);

        var strings = new List<string>();
        Collect(report, strings, []);
        Assert.NotEmpty(strings);
        foreach (var s in strings)
        {
            Assert.DoesNotContain("SECRET-SUMMARY-TEXT", s, StringComparison.Ordinal);
            Assert.DoesNotContain("SESSION-ABC", s, StringComparison.Ordinal);
            Assert.DoesNotContain("REQ-SECRET-1", s, StringComparison.Ordinal);
        }
    }

    private static void Collect(object? value, List<string> strings, HashSet<object> seen)
    {
        switch (value)
        {
            case null:
                return;
            case string s:
                strings.Add(s);
                return;
            case IDictionary dict:
                foreach (DictionaryEntry kv in dict)
                {
                    Collect(kv.Key, strings, seen);
                    Collect(kv.Value, strings, seen);
                }
                return;
            case IEnumerable seq:
                foreach (var item in seq)
                {
                    Collect(item, strings, seen);
                }
                return;
        }

        var type = value.GetType();
        if (type.IsPrimitive || type.IsEnum || type == typeof(DateTimeOffset) || !seen.Add(value))
        {
            return;
        }

        foreach (var p in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (p.GetIndexParameters().Length == 0)
            {
                Collect(p.GetValue(value), strings, seen);
            }
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class TamperedStore(params AuditEntry[] entries) : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => throw new NotSupportedException();

        public async IAsyncEnumerable<AuditEntry> QueryAsync(
            AuditQuery query, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            foreach (var e in entries)
            {
                yield return e;
            }
            await Task.CompletedTask;
        }
    }
}
