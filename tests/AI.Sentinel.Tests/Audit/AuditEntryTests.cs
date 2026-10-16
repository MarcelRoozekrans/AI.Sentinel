using System;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditEntryTests
{
    [Fact]
    public void AuditEntry_PolicyCode_DefaultsToNull()
    {
        var entry = new AuditEntry(
            Id: "x",
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "h",
            PreviousHash: null,
            Severity: Severity.Low,
            DetectorId: "test",
            Summary: "summary");

        Assert.Null(entry.PolicyCode);
    }

    [Fact]
    public void AuditEntry_PolicyCode_PreservesValueWhenSet()
    {
        var entry = new AuditEntry(
            Id: "x",
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "h",
            PreviousHash: null,
            Severity: Severity.High,
            DetectorId: "AUTHZ-DENY",
            Summary: "summary")
        {
            PolicyCode = "tenant_inactive",
        };

        Assert.Equal("tenant_inactive", entry.PolicyCode);
    }

    private static readonly AuditEntry FullEntry =
        new("x", new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero), "h", "p", Severity.High, "AUTHZ-DENY", "summary")
        {
            PolicyCode = "tenant_inactive",
            SessionId = "sess-1",
            Source = AuditSources.Mcp,
        };

    [Fact]
    public void AuditEntry_Json_KeepsTheWireFormat()
    {
        // The NDJSON forwarder and the dashboard export write this shape; the init properties
        // must serialize exactly as the former positional parameters did.
        var json = JsonSerializer.Serialize(FullEntry, AuditJsonContext.Default.AuditEntry);

        Assert.Equal(
            """{"Id":"x","Timestamp":"2026-10-13T12:00:00+00:00","Hash":"h","PreviousHash":"p","Severity":"High","DetectorId":"AUTHZ-DENY","Summary":"summary","PolicyCode":"tenant_inactive","SessionId":"sess-1","Source":"mcp"}""",
            json);
    }

    [Fact]
    public void AuditEntry_Json_RoundTripsTheInitProperties()
    {
        var json = JsonSerializer.Serialize(FullEntry, AuditJsonContext.Default.AuditEntry);

        Assert.Equal(FullEntry, JsonSerializer.Deserialize(json, AuditJsonContext.Default.AuditEntry));
    }

    [Fact]
    public void AuditEntry_Json_MissingOptionalFieldsDeserializeAsNull()
    {
        const string json = """{"Id":"x","Timestamp":"2026-10-13T12:00:00+00:00","Hash":"h","PreviousHash":null,"Severity":"Low","DetectorId":"SEC-01","Summary":"s"}""";

        var entry = JsonSerializer.Deserialize(json, AuditJsonContext.Default.AuditEntry);

        Assert.NotNull(entry);
        Assert.Null(entry.PolicyCode);
        Assert.Null(entry.SessionId);
        Assert.Null(entry.Source);
    }

    [Fact]
    public void AuditQuery_Defaults_MatchTheFormerParameterDefaults()
    {
        var query = new AuditQuery();

        Assert.Null(query.MinSeverity);
        Assert.Null(query.From);
        Assert.Null(query.To);
        Assert.Equal(200, query.PageSize);
        Assert.False(query.Reverse);
        Assert.Null(query.SessionId);
        Assert.Null(query.Source);
    }
}
