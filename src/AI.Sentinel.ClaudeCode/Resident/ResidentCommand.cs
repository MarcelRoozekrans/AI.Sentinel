using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The verb a hook starts itself with to run the resident process: <c>sentinel-hook --resident</c>. Both hook CLIs carry it, and
/// one process serves both, because the state folder and the lock are per user.
/// </summary>
internal static class ResidentCommand
{
    /// <summary>The argument that selects this command.</summary>
    public const string Verb = "--resident";

    public static bool Matches(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Length > 0 && string.Equals(args[0], Verb, StringComparison.Ordinal);
    }

    /// <summary>Runs the process until it exits; the exit code is 0 when it ended on its own or another instance runs, and 1 when
    /// it could not listen or is not turned on.</summary>
    public static async Task<int> RunAsync(IReadOnlyList<IRegoCompiler> compilers, TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(compilers);
        ArgumentNullException.ThrowIfNull(stderr);
        if (ResidentSettings.FromEnvironment(ResidentSettings.ProcessEnvironment()) is not { } settings)
        {
            await stderr.WriteLineAsync($"the resident process is off: set {ResidentSettings.EnableVariable}=on").ConfigureAwait(false);
            return 1;
        }

        var exit = await ResidentHost.RunAsync(settings, compilers, CancellationToken.None).ConfigureAwait(false);
        return exit == ResidentExit.Failed ? 1 : 0;
    }
}
