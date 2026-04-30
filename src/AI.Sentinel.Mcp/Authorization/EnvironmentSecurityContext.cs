using System;
using System.Collections.Generic;
using AI.Sentinel.Authorization;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Mcp.Authorization;

/// <summary>
/// Resolves caller identity from <c>SENTINEL_MCP_CALLER_ID</c> and
/// <c>SENTINEL_MCP_CALLER_ROLES</c> (comma-separated) environment variables set
/// by the MCP host. Falls back to <see cref="AnonymousSecurityContext.Instance"/>
/// when <c>SENTINEL_MCP_CALLER_ID</c> is absent or blank.
/// </summary>
public sealed class EnvironmentSecurityContext : ISecurityContext
{
    /// <summary>Environment variable name for the caller identifier.</summary>
    public const string CallerIdEnvVar = "SENTINEL_MCP_CALLER_ID";

    /// <summary>Environment variable name for the comma-separated caller roles list.</summary>
    public const string CallerRolesEnvVar = "SENTINEL_MCP_CALLER_ROLES";

    /// <inheritdoc />
    public string Id { get; }

    /// <inheritdoc />
    public IReadOnlySet<string> Roles { get; }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string> Claims { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    private EnvironmentSecurityContext(string id, IReadOnlySet<string> roles)
    {
        Id = id;
        Roles = roles;
    }

    /// <summary>
    /// Returns an instance built from <c>SENTINEL_MCP_CALLER_ID</c> /
    /// <c>SENTINEL_MCP_CALLER_ROLES</c> env vars, or
    /// <see cref="AnonymousSecurityContext.Instance"/> when no caller id is set.
    /// </summary>
    public static ISecurityContext FromEnvironment()
    {
        var id = Environment.GetEnvironmentVariable(CallerIdEnvVar);
        if (string.IsNullOrWhiteSpace(id))
        {
            return AnonymousSecurityContext.Instance;
        }

        var rolesEnv = Environment.GetEnvironmentVariable(CallerRolesEnvVar) ?? string.Empty;
        var roles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in rolesEnv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            roles.Add(role);
        }

        return new EnvironmentSecurityContext(id, roles);
    }
}
