using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Events;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>An entry whose summary does not have the shape the mapper reads still becomes an event, with nothing read from the text (#661).</summary>
public sealed class AuditEventMapperTests
{
    private static AuditEntry Entry(string detector, string summary, string? code = null) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, string.Empty, null, Severity.Medium, detector, summary)
        {
            ToolKind = "shell",
            Node = "node-a",
            PolicyCode = code,
        };

    [Fact]
    public void An_outcome_entry_that_does_not_parse_is_sent_as_a_finding_without_its_text()
    {
        var mapped = AuditEventMapper.Map(Entry(OutcomeAudit.DetectorId, "deny without the expected parts"), _ => false);

        Assert.NotNull(mapped);
        Assert.Equal("finding", mapped.Outcome);
        Assert.Null(mapped.Policies);
        Assert.Null(mapped.Reason);
    }

    [Fact]
    public void A_redaction_entry_with_no_counts_is_sent_without_counts()
    {
        var mapped = AuditEventMapper.Map(Entry("REDACT", "something else", AuditEntryRedactionExtensions.RedactedPolicyCode), _ => false);

        Assert.NotNull(mapped);
        Assert.Equal("redacted", mapped.Outcome);
        Assert.Null(mapped.Redactions);
    }
}
