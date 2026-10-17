using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditEntryKindsTests
{
    private static AuditEntry Entry(Severity severity, string? policyCode, string detectorId = "X-01") =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "deadbeef00000000", null, severity, detectorId, "s")
        {
            PolicyCode = policyCode,
        };

    [Theory]
    [InlineData(AuditEntryRedactionExtensions.RedactedPolicyCode)]
    [InlineData(AuditEntryKinds.DisclosedPolicyCode)]
    [InlineData(AuditEntryKinds.ApprovedPolicyCode)]
    [InlineData(AuditEntryKinds.DeniedPolicyCode)]
    [InlineData(AuditEntryKinds.ExpiredPolicyCode)]
    [InlineData(AuditEntryKinds.TimedOutPolicyCode)]
    public void IsInformational_RedactedDisclosedApproval_True(string code) =>
        Assert.True(AuditEntryKinds.IsInformational(Entry(Severity.None, code)));

    [Fact]
    public void IsInformational_DetectionOrAuthzDeny_False()
    {
        Assert.False(AuditEntryKinds.IsInformational(Entry(Severity.High, "AUTHZ-DENY", "AUTHZ-DENY")));
        Assert.False(AuditEntryKinds.IsInformational(Entry(Severity.None, null)));
    }
}
