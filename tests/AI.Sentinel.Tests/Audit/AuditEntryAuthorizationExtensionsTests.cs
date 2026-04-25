using System;
using System.Collections.Generic;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditEntryAuthorizationExtensionsTests
{
    [Fact]
    public void AuthorizationDeny_HasCorrectShape()
    {
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("user"),
            receiver: new AgentId("assistant"),
            session: SessionId.New(),
            callerId: "alice",
            roles: new HashSet<string>(StringComparer.Ordinal) { "user" },
            toolName: "Bash",
            policyName: "admin-only",
            reason: "missing role 'admin'");

        Assert.Equal("AUTHZ-DENY", entry.DetectorId);
        Assert.Equal(Severity.High, entry.Severity);
        Assert.Contains("alice", entry.Summary, StringComparison.Ordinal);
        Assert.Contains("Bash", entry.Summary, StringComparison.Ordinal);
        Assert.Contains("admin-only", entry.Summary, StringComparison.Ordinal);
        Assert.Contains("missing role", entry.Summary, StringComparison.Ordinal);
    }
}
