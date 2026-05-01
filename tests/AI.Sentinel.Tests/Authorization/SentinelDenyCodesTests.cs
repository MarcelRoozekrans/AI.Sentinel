using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class SentinelDenyCodesTests
{
    [Fact]
    public void Constants_MatchWireFormat()
    {
        // Locks the wire format. The constants exist for clarity; the strings are the contract.
        // A future refactor that renames the codes to "make them more uniform" would fail here
        // BEFORE breaking every audit consumer / SIEM dashboard / hook receipt parser.
        Assert.Equal("policy_denied",            SentinelDenyCodes.PolicyDenied);
        Assert.Equal("policy_not_registered",    SentinelDenyCodes.PolicyNotRegistered);
        Assert.Equal("policy_exception",         SentinelDenyCodes.PolicyException);
        Assert.Equal("approval_required",        SentinelDenyCodes.ApprovalRequired);
        Assert.Equal("approval_store_exception", SentinelDenyCodes.ApprovalStoreException);
        Assert.Equal("approval_state_unknown",   SentinelDenyCodes.ApprovalStateUnknown);
    }
}
