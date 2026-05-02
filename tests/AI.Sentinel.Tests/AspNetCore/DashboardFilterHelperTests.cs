using System;
using System.Collections.Generic;
using System.Linq;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardFilterHelperTests
{
    [Theory]
    [InlineData("SEC-01",       "security",      true)]
    [InlineData("SEC-21",       "security",      true)]
    [InlineData("HAL-08",       "security",      false)]
    [InlineData("HAL-08",       "hallucination", true)]
    [InlineData("OPS-12",       "operational",   true)]
    [InlineData("AUTHZ-DENY",   "authorization", true)]
    [InlineData("SEC-01",       "authorization", false)]
    public void IsInCategory_PrefixMatch_KnownCategories(string detectorId, string category, bool expected)
    {
        Assert.Equal(expected, DashboardHandlers.IsInCategory(detectorId, category));
    }

    [Theory]
    [InlineData("SEC-01", "")]
    [InlineData("HAL-08", null)]
    [InlineData("OPS-12", "unknown_category")]
    public void IsInCategory_NullEmptyOrUnknown_ReturnsTrue(string detectorId, string? category)
    {
        Assert.True(DashboardHandlers.IsInCategory(detectorId, category));
    }

    private static AuditEntry NewEntry(string detectorId, string summary, string sessionId = "sess-1") =>
        new(
            Id:           Guid.NewGuid().ToString("N"),
            Timestamp:    DateTimeOffset.UtcNow,
            Hash:         "h",
            PreviousHash: null,
            Severity:     Severity.Medium,
            DetectorId:   detectorId,
            Summary:      summary,
            PolicyCode:   null,
            SessionId:    sessionId);

    [Fact]
    public void FilterAuditEntries_NoFilters_ReturnsAll()
    {
        var entries = new[]
        {
            NewEntry("SEC-01",     "prompt injection attempt"),
            NewEntry("HAL-08",     "hallucinated citation"),
            NewEntry("AUTHZ-DENY", "policy denied delete_database"),
        };
        var result = DashboardHandlers.FilterAuditEntries(entries, category: null, q: null, session: null).ToList();
        Assert.Equal(3, result.Count);
    }

    [Fact]
    public void FilterAuditEntries_CategoryOnly_FiltersByPrefix()
    {
        var entries = new[]
        {
            NewEntry("SEC-01",     "x"),
            NewEntry("HAL-08",     "x"),
            NewEntry("AUTHZ-DENY", "x"),
        };
        var result = DashboardHandlers.FilterAuditEntries(entries, category: "security", q: null, session: null).ToList();
        Assert.Single(result);
        Assert.Equal("SEC-01", result[0].DetectorId);
    }

    [Fact]
    public void FilterAuditEntries_SessionOnly_FiltersBySessionId()
    {
        var entries = new[]
        {
            NewEntry("SEC-01", "x", sessionId: "sess-A"),
            NewEntry("SEC-01", "x", sessionId: "sess-B"),
            NewEntry("HAL-08", "x", sessionId: "sess-A"),
        };
        var result = DashboardHandlers.FilterAuditEntries(entries, category: null, q: null, session: "sess-A").ToList();
        Assert.Equal(2, result.Count);
        Assert.All(result, e => Assert.Equal("sess-A", e.SessionId));
    }

    [Fact]
    public void FilterAuditEntries_QueryOnly_FreeTextMatchesSummaryCaseInsensitive()
    {
        var entries = new[]
        {
            NewEntry("SEC-01", "Tool call to delete_database blocked"),
            NewEntry("SEC-01", "Hallucinated function reference"),
            NewEntry("OPS-12", "Tool call to DELETE_DATABASE detected"),
        };
        var result = DashboardHandlers.FilterAuditEntries(entries, category: null, q: "delete_database", session: null).ToList();
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void FilterAuditEntries_AllThreeIntersect_AndsTogether()
    {
        var entries = new[]
        {
            NewEntry("SEC-01",     "delete_database",  sessionId: "sess-A"),
            NewEntry("SEC-01",     "delete_database",  sessionId: "sess-B"),
            NewEntry("AUTHZ-DENY", "delete_database",  sessionId: "sess-A"),
            NewEntry("SEC-01",     "prompt injection", sessionId: "sess-A"),
        };
        var result = DashboardHandlers.FilterAuditEntries(entries, category: "security", q: "delete_database", session: "sess-A").ToList();
        Assert.Single(result);
        Assert.Equal("sess-A", result[0].SessionId);
        Assert.Equal("delete_database", result[0].Summary);
    }
}
