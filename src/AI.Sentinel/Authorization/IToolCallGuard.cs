using System.Text.Json;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

/// <summary>Evaluates whether a tool call is authorized for the given caller. Runs before the detection pipeline.</summary>
public interface IToolCallGuard
{
    /// <summary>Returns <see cref="AuthorizationDecision.Allow"/> or a deny decision describing the policy that refused.</summary>
    /// <param name="caller">Identity of the caller invoking the tool.</param>
    /// <param name="toolName">Name of the tool being invoked.</param>
    /// <param name="args">Tool arguments serialised as a JSON element.</param>
    /// <param name="ct">Cancellation token.</param>
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default);
}
