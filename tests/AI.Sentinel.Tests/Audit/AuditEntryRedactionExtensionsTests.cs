using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditEntryRedactionExtensionsTests
{
    [Fact]
    public void Redaction_IsInformational_CountsOnly_TypesInOrdinalOrder()
    {
        var entry = AuditEntryRedactionExtensions.Redaction(
            "SEC-23",
            new Dictionary<string, int>(StringComparer.Ordinal) { ["IBAN"] = 1, ["EMAIL"] = 2, ["DATE_OF_BIRTH"] = 1 },
            "s1");

        Assert.Equal("SEC-23", entry.DetectorId);
        Assert.Equal(Severity.None, entry.Severity);
        Assert.Equal("REDACTED", entry.PolicyCode);
        Assert.Equal(AuditEntryRedactionExtensions.RedactedPolicyCode, entry.PolicyCode);
        Assert.Equal("Redacted 1 DATE_OF_BIRTH, 2 EMAIL, 1 IBAN", entry.Summary);
        Assert.Equal("s1", entry.SessionId);
        Assert.Equal(string.Empty, entry.Hash);
    }
}
