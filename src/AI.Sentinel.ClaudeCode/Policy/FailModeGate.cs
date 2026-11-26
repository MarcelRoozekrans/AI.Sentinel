using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// The decision for a call that no policy decision can be made for (#673, ADR-237): closed denies with guidance, ask asks. A read
/// or a search inside the repository stays allowed in both modes, so the developer can still look at the code. Inside means after
/// symbolic links are followed, in the path and in the repository root, so a link that leads out of the repository is not exempt.
/// </summary>
internal static class FailModeGate
{
    /// <summary>The source of a decision the fail mode made.</summary>
    public const string Source = "fail-mode";

    /// <summary>The reason of a read that stays allowed.</summary>
    private const string ReadOnlyReason = "A read or search inside the repository stays allowed while no policy decision can be made.";

    /// <summary>The decision for <paramref name="input"/>, with <paramref name="context"/> saying why nothing decided it.</summary>
    public static OutcomeDecision Decide(FailModeContext context, PolicyInput input, string? repositoryRoot, string version = "")
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(input);
        if (IsReadOnlyInRepository(input, repositoryRoot))
        {
            return new OutcomeDecision(DecisionOutcome.Allow, ReadOnlyReason, [Source], version);
        }

        var mode = context.Asks ? "ask" : "closed";
        var next = context.NeedsSignIn
            ? "Sign in to the AI.Sentinel server, then run the call again."
            : "Check the connection to the AI.Sentinel server so the profile can refresh, or ask a policy owner for help.";
        var reason = $"AI.Sentinel could not decide this call because {context.Cause}, so no policy decision could be made and the fail mode is {mode}. {next}";
        return new OutcomeDecision(context.Asks ? DecisionOutcome.Ask : DecisionOutcome.Deny, reason, [Source], version);
    }

    /// <summary>
    /// <paramref name="output"/> combined with the fail mode when a server is configured and no usable profile is cached; as it is
    /// otherwise, and for a <see langword="null"/> context, which is how a hook without a server behaves.
    /// </summary>
    public static HookOutput ApplyMissingProfile(
        FailModeContext? context, HookOutput output, string cli, string toolName, JsonElement toolInput, string session, string? repositoryRoot)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (context is not { ServerConfigured: true, ProfileUsable: false })
        {
            return output;
        }

        var input = PolicyInputBuilder.Build(cli, toolName, toolInput, session, [], repositoryRoot);
        var existing = output.Outcome ?? OutcomeDecision.FromHook(output.Decision, output.Reason, LocalPolicy.ChecksSource);
        return OutcomeDecision.Strictest([existing, Decide(context, input, repositoryRoot)]).ToHookOutput(canAsk: true);
    }

    private static bool IsReadOnlyInRepository(PolicyInput input, string? repositoryRoot)
    {
        if (repositoryRoot is null
            || (!string.Equals(input.Kind, ToolKind.Read.ToWire(), StringComparison.Ordinal) && !string.Equals(input.Kind, ToolKind.Search.ToWire(), StringComparison.Ordinal))
            || input.Details.Paths is not { Count: > 0 } paths)
        {
            return false;
        }

        var root = LinksFollowed(Path.GetFullPath(repositoryRoot));
        return root is not null && paths.All(p => Path.IsPathRooted(p.Path) && LinksFollowed(p.Path) is { } real && PolicyInputBuilder.IsInside(real, root));
    }

    /// <summary>
    /// <paramref name="full"/> with every symbolic link in it followed, component by component, so a link in a parent folder counts
    /// as much as one at the end. A part that does not exist is kept as written. <see langword="null"/> when a link cannot be read or
    /// the links loop.
    /// </summary>
    private static string? LinksFollowed(string full)
    {
        const int maxLinks = 40;
        var followed = 0;
        var pending = new Stack<string>();
        var current = Path.GetPathRoot(full)!;
        PushParts(pending, full[current.Length..]);
        while (pending.Count > 0)
        {
            var next = Path.Combine(current, pending.Pop());
            FileSystemInfo info = new FileInfo(next);
            if (info.LinkTarget is null && Directory.Exists(next))
            {
                info = new DirectoryInfo(next);
            }

            string? target;
            try
            {
                target = info.LinkTarget;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }

            if (target is null)
            {
                current = next;
                continue;
            }

            if (++followed > maxLinks)
            {
                return null;
            }

            // The target is resolved against the folder that holds the link, and its own parts are walked again.
            var resolved = Path.GetFullPath(target, current);
            current = Path.GetPathRoot(resolved)!;
            PushParts(pending, resolved[current.Length..]);
        }

        return current;
    }

    private static void PushParts(Stack<string> pending, string relative)
    {
        var parts = relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        for (var i = parts.Length - 1; i >= 0; i--)
        {
            pending.Push(parts[i]);
        }
    }
}
