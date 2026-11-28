using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.SignIn;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>
/// What a hook decides about the events of one call (#661): whether its audit entries are routed to the server, and with which tool kind
/// and node. A call is routed only with a server configured and a repository that may send events: in strict repository mode, with no
/// node map cached, or when the map cannot be read, nothing is routed and so nothing is sent.
/// </summary>
internal static class EventRouting
{
    /// <summary>The tool kind and node to route the entries of this call with, or <see langword="null"/> for no events.</summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="cli">One of <see cref="PolicyClis"/>.</param>
    /// <param name="toolName">The tool of the call; <see langword="null"/> for a prompt.</param>
    /// <param name="workingDirectory">The working directory of the hook.</param>
    public static (string ToolKind, string? Node)? Resolve(
        IReadOnlyDictionary<string, string?> env, string cli, string? toolName, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (SignInSettings.FromEnvironment(env, out _) is null)
        {
            return null;
        }

        try
        {
            // Only the repository and its node are needed here, not the profiles that judge the call.
            if (RepositoryScope.Open(env, workingDirectory) is not { SendsEvents: true } scope)
            {
                return null;
            }

            return (ToolKinds.Map(cli, toolName).ToWire(), scope.Unowned ? null : scope.Node);
        }
        catch (Exception e) when (e is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            // An unreadable node map blocks the call elsewhere; here it only means no events.
            return null;
        }
    }
}
