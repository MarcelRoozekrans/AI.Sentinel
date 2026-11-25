namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The internal command a hook starts itself with to compile a policy: <c>--compile-policy &lt;source-folder&gt;
/// &lt;output&gt; [--unrestricted]</c>. It runs the interop compiler, a Go library, in this child process only, so a crash
/// of it ends the child and the hook, which waits for it, blocks the call. The module is written to the output as
/// <see cref="PolicyCache"/> writes a file, with its digest in front.
/// </summary>
internal static class PolicyCompileCommand
{
    /// <summary>The first argument that selects this command.</summary>
    public const string Verb = "--compile-policy";

    /// <summary>The flag that leaves out the capabilities document, so a builtin that reaches outside the process compiles.</summary>
    public const string Unrestricted = "--unrestricted";

    /// <summary>The module was written.</summary>
    public const int Compiled = 0;

    /// <summary>The policy does not compile; the compiler message is on stderr.</summary>
    public const int NotCompiled = 3;

    /// <summary>The compiler cannot run here; the reason is on stderr.</summary>
    public const int NoCompiler = 4;

    /// <summary>The arguments are not those of this command.</summary>
    public const int BadUsage = 64;

    public static bool Matches(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Length > 0 && string.Equals(args[0], Verb, StringComparison.Ordinal);
    }

    /// <summary>Compiles and returns the exit code of the child.</summary>
    public static int Run(string[] args, TextWriter stderr) => Run(args, stderr, InteropRegoCompiler.Unavailable());

    /// <param name="args">The command line.</param>
    /// <param name="stderr">Where the usage, the reason there is no compiler or the compiler message goes.</param>
    /// <param name="unavailable">Why the interop compiler cannot run here, or <see langword="null"/> when it can.</param>
    internal static int Run(string[] args, TextWriter stderr, string? unavailable)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(stderr);
        if (args.Length is < 3 or > 4 || !Matches(args) || (args.Length == 4 && !string.Equals(args[3], Unrestricted, StringComparison.Ordinal)))
        {
            stderr.WriteLine($"usage: {Verb} <source-folder> <output> [{Unrestricted}]");
            return BadUsage;
        }

        if (unavailable is not null)
        {
            stderr.WriteLine(unavailable);
            return NoCompiler;
        }

        try
        {
            PolicyCache.Write(args[2], InteropRegoCompiler.CompileFolder(args[1], restrictBuiltins: args.Length == 3));
            return Compiled;
        }
        catch (RegoCompileException e)
        {
            stderr.WriteLine(e.Message);
            return NotCompiled;
        }
    }
}
