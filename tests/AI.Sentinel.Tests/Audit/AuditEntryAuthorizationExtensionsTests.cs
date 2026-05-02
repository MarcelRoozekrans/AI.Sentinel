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

    [Fact]
    public void AuthorizationDeny_PolicyCode_PersistsOnAuditEntry()
    {
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("user"),
            receiver: new AgentId("agent"),
            session: SessionId.New(),
            callerId: "u1",
            roles: new HashSet<string>(StringComparer.Ordinal),
            toolName: "Bash",
            policyName: "TenantActive",
            reason: "Tenant 'acme' is in evicted state",
            policyCode: "tenant_inactive");

        Assert.Equal("tenant_inactive", entry.PolicyCode);
        Assert.Contains("tenant_inactive", entry.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizationDeny_DefaultsToPolicyDeniedWhenCodeOmitted()
    {
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("user"),
            receiver: new AgentId("agent"),
            session: SessionId.New(),
            callerId: "u1",
            roles: new HashSet<string>(StringComparer.Ordinal),
            toolName: "Bash",
            policyName: "AdminOnly",
            reason: "Policy denied");

        Assert.Equal("policy_denied", entry.PolicyCode);
    }

    [Fact]
    public void AuthorizationDeny_PopulatesSessionIdField_FromSessionParameter()
    {
        var session = new SessionId("sess-test-123");
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("u"),
            receiver: new AgentId("a"),
            session: session,
            callerId: "u1",
            roles: new HashSet<string>(StringComparer.Ordinal),
            toolName: "Bash",
            policyName: "TenantActive",
            reason: "Tenant evicted");

        Assert.Equal("sess-test-123", entry.SessionId);
    }
}
