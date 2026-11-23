namespace RegoAot;

/// <summary>One decision, as the policy entrypoint returns it.</summary>
internal sealed record Decision(string Outcome, IReadOnlyList<string> Reasons);

internal interface IEvaluator : IDisposable
{
    Decision Evaluate(string inputJson);
}

/// <summary>A way to evaluate the compiled bundles. A route says why it is unavailable instead of throwing.</summary>
internal interface IRoute
{
    string Name { get; }

    /// <summary>The modes the route can be measured in. --check evaluates every case in every mode except warm.</summary>
    IReadOnlyList<string> Modes { get; }

    string? Unavailable();

    IEvaluator Create(BundleSet set, string mode, string cacheDir);

    /// <summary>Writes the precompiled artifacts of the module into the cache directory.</summary>
    void Prepare(BundleSet set, string cacheDir);

    /// <summary>The builtins that reach outside the process which the set uses and the route refuses when it validates the set. Empty when the set is accepted.</summary>
    IReadOnlyList<string> Validate(BundleSet set);

    /// <summary>Evaluates a set that was not validated, as if a bundle had slipped past validation.</summary>
    Decision RunUnvalidated(BundleSet set, string inputJson);

    /// <summary>Builtins the route evaluates at runtime instead of refusing; a documented gap that validation has to cover.</summary>
    IReadOnlyList<string> RuntimeGaps { get; }
}

internal static class Routes
{
    public static IEnumerable<ICompiler> Compilers() => [new InteropCompiler(), new OpaCliCompiler()];

    public static IEnumerable<IRoute> All()
    {
        foreach (var compiler in Compilers())
        {
            yield return new WasmtimeRoute(compiler);
        }
        yield return new OpaEvalRoute();
        yield return new OpaServerRoute();
        yield return new RegoCppRoute();
    }
}

internal static class Cache
{
    /// <summary>
    /// Precompiled artifacts live under a per-user directory named by the module hash, never in the shared
    /// temp directory: the native code is loaded and run, so another user must not be able to plant it.
    /// </summary>
    public static string Dir(BundleSet set)
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir))
        {
            baseDir = Path.Combine(Path.GetTempPath(), "regoaot-" + Environment.UserName);
        }

        return Path.Combine(baseDir, "regoaot-cache", set.Hash);
    }

    /// <summary>Creates the directory owner-only on Unix and refuses one that anyone else can write.</summary>
    public static void Create(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
            return;
        }

        const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(dir, OwnerOnly);
        var parent = Path.GetDirectoryName(dir)!;
        foreach (var d in Path.GetFileName(parent) == "regoaot-cache" ? new[] { dir, parent } : [dir])
        {
            if ((File.GetUnixFileMode(d) & ~OwnerOnly) != 0)
            {
                File.SetUnixFileMode(d, OwnerOnly);
            }
        }
    }

    /// <summary>Writes the artifact and the digest of it. The digest is the integrity check made before the bytes are loaded.</summary>
    public static void WriteVerified(string path, byte[] bytes)
    {
        File.WriteAllBytes(path, bytes);
        File.WriteAllText(path + ".sha256", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)));
    }

    /// <summary>
    /// Reads the artifact and checks it against its digest. A missing file, a missing digest or a mismatch
    /// throws, and the caller decides what that means. The bytes that were hashed are the bytes that are loaded.
    /// </summary>
    public static byte[] ReadVerified(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var expected = File.ReadAllText(path + ".sha256").Trim();
        var actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        return string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)
            ? bytes
            : throw new InvalidDataException($"{Path.GetFileName(path)} does not match its recorded digest");
    }
}
