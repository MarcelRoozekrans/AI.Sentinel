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
}

internal static class Routes
{
    public static IEnumerable<IRoute> All()
    {
        ICompiler compiler = new OpaCliCompiler();
        yield return new WasmtimeRoute(compiler);
    }
}

internal static class Cache
{
    /// <summary>Precompiled artifacts live under a directory named by the module hash.</summary>
    public static string Dir(BundleSet set) => Path.Combine(Path.GetTempPath(), "regoaot-cache", set.Hash);
}
