using System.Text.Json;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference arg-aware policy: denies <c>Bash</c> calls whose <c>path</c> argument starts with <c>/etc/</c> or <c>/sys/</c>. Opt-in via DI registration.</summary>
[AuthorizationPolicy("no-system-paths")]
public sealed class NoSystemPathsPolicy : ToolCallAuthorizationPolicy
{
    /// <summary>Allows non-<c>Bash</c> tool calls; for <c>Bash</c>, denies when <c>path</c> begins with a system prefix.</summary>
    protected override bool IsAuthorized(IToolCallSecurityContext ctx)
    {
        if (!string.Equals(ctx.ToolName, "Bash", StringComparison.Ordinal)) return true;
        if (!ctx.Args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String) return true;
        var path = p.GetString();
        return path is null || (!path.StartsWith("/etc/", StringComparison.Ordinal)
                              && !path.StartsWith("/sys/", StringComparison.Ordinal));
    }
}
