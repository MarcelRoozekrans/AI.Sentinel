using System;
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
            Summary: "summary",
            PolicyCode: "tenant_inactive");

        Assert.Equal("tenant_inactive", entry.PolicyCode);
    }
}
