using System.Text.Json.Nodes;
using Rego;

namespace RegoAot;

/// <summary>
/// The Rego NuGet package, a .NET binding over rego-cpp from Microsoft. The engine is a C++ interpreter
/// in a native library, not .NET code. Cached mode loads a bundle that rego-cpp built and saved in its
/// binary format.
/// </summary>
internal sealed class RegoCppRoute : IRoute
{
    private const string Query = "data.sentinel.decision";

    public string Name => "rego-cpp";

    public IReadOnlyList<string> Modes => ["cached", "cold", "warm"];

    public string? Unavailable() => null;

    public void Prepare(BundleSet set, string cacheDir)
    {
        Directory.CreateDirectory(cacheDir);
        var rego = Load(set);
        rego.SaveBundle(BundlePath(set, cacheDir), rego.Build(Query), BundleFormat.Binary);
    }

    public IEvaluator Create(BundleSet set, string mode, string cacheDir)
    {
        if (mode == "cold")
        {
            return new Evaluator(Load(set), null);
        }

        var rego = new Interpreter();
        return new Evaluator(rego, rego.LoadBundle(BundlePath(set, cacheDir), BundleFormat.Binary));
    }

    private static Interpreter Load(BundleSet set)
    {
        var rego = new Interpreter();
        foreach (var file in set.Files)
        {
            rego.AddModule(file, File.ReadAllText(Path.Combine(set.Root, file)));
        }

        return rego;
    }

    private static string BundlePath(BundleSet set, string cacheDir) => Path.Combine(cacheDir, set.Hash + ".rego-bundle");

    private sealed class Evaluator(Interpreter rego, Bundle? bundle) : IEvaluator
    {
        public Decision Evaluate(string inputJson)
        {
            rego.SetInputTerm(inputJson);
            var output = bundle is null ? rego.Query(Query) : rego.QueryBundle(bundle);
            if (!output.Ok || output.Count == 0)
            {
                return new Decision("defer", []);
            }

            var expressions = JsonNode.Parse(output.Expressions().ToJson())!;
            return OpaResult.Parse(expressions is JsonArray array ? array[0] : expressions);
        }

        public void Dispose()
        {
        }
    }
}
