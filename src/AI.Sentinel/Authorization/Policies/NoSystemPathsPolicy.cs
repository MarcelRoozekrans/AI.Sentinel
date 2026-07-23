using System.Text.Json;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference arg-aware policy: denies <c>Bash</c> calls whose <c>path</c> argument starts with <c>/etc/</c> or <c>/sys/</c>. Opt-in via DI registration.</summary>
[Policy("no-system-paths")]
public sealed class NoSystemPathsPolicy : ToolCallAuthorizationPolicy
{
    /// <summary>Allows non-<c>Bash</c> tool calls; for <c>Bash</c>, denies when <c>path</c> begins with a system prefix.</summary>
    protected override ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        IToolCallSecurityContext ctx, CancellationToken ct)
    {
        if (!string.Equals(ctx.ToolName, "Bash", StringComparison.Ordinal)) return new(Allow());
        if (!ctx.Args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String) return new(Allow());
        var path = p.GetString();
        return new(path is null || (!path.StartsWith("/etc/", StringComparison.Ordinal)
                                  && !path.StartsWith("/sys/", StringComparison.Ordinal))
            ? Allow()
            : Deny($"Bash 'path' argument '{path}' targets a protected system directory"));
    }
}
