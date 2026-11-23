using RegoAot;

if (args.Contains("--once", StringComparer.Ordinal))
{
    return Measure.Once(args);
}

if (args.Contains("--compile-once", StringComparer.Ordinal))
{
    return Measure.CompileOnce(args);
}

if (args.Contains("--choose", StringComparer.Ordinal))
{
    // The chosen route is the first available one in this order, and nothing when none is. CI measures only that.
    string[] preferred = ["wasmtime+interop", "wasmtime+opa-cli", "rego-cpp", "opa-eval"];
    var available = Routes.All().Where(r => r.Unavailable() is null).Select(r => r.Name).ToList();
    Console.WriteLine(preferred.FirstOrDefault(available.Contains) ?? "");
    return 0;
}

if (args.Contains("--measure", StringComparer.Ordinal))
{
    return Measure.Run(args);
}

return Check.Run(args);
