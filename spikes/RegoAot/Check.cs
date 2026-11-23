namespace RegoAot;

internal static class Check
{
    public static string AppDir => AppContext.BaseDirectory;

    public static int Run(string[] args)
    {
        if (!args.Contains("--check", StringComparer.Ordinal))
        {
            Console.WriteLine("usage: RegoAot --check | --measure [--runs N] [--routes a,b]");
            return 2;
        }

        var failures = 0;
        var set = BundleSet.Load(Path.Combine(AppDir, "policy"));
        var cases = Cases.Load(Path.Combine(AppDir, "inputs"));
        Console.WriteLine($"bundles: {string.Join(", ", set.Bundles)}");
        Console.WriteLine($"module id (sha256 of all bundles): {set.Hash}");
        Console.WriteLine($"cases: {cases.Count}");

        failures += CheckHash(set);

        var routes = Routes.All().ToList();
        var available = 0;
        foreach (var route in routes)
        {
            var why = route.Unavailable();
            if (why is not null)
            {
                Console.WriteLine($"route {route.Name}: unavailable ({why})");
                continue;
            }

            available++;
            failures += CheckRoute(route, set, cases);
        }

        if (available == 0)
        {
            Console.WriteLine("no route is available on this machine, so no outcome was compared; the spike reports that none works");
            return failures == 0 ? 0 : 1;
        }

        Console.WriteLine(failures == 0 ? "check: OK" : $"check: {failures} failure(s)");
        return failures == 0 ? 0 : 1;
    }

    private static int CheckHash(BundleSet set)
    {
        var failures = 0;
        var again = BundleSet.Load(set.Root);
        failures += Expect(again.Hash == set.Hash, "module id is stable across loads");
        failures += Expect(set.Bundles.Count >= 3, $"{set.Bundles.Count} bundles share one module");

        var copy = Path.Combine(Path.GetTempPath(), "regoaot-" + Guid.NewGuid().ToString("N"));
        try
        {
            CopyDirectory(set.Root, copy);
            var first = Directory.EnumerateFiles(copy, "*.rego", SearchOption.AllDirectories).Order(StringComparer.Ordinal).First();
            File.AppendAllText(first, "\n# changed\n");
            failures += Expect(BundleSet.Load(copy).Hash != set.Hash, "module id changes when one bundle changes");
        }
        finally
        {
            Directory.Delete(copy, recursive: true);
        }

        return failures;
    }

    private static int CheckRoute(IRoute route, BundleSet set, List<Case> cases)
    {
        var failures = 0;
        var cacheDir = Cache.Dir(set);
        route.Prepare(set, cacheDir);
        foreach (var mode in route.Modes.Where(m => m != "warm"))
        {
            using var eval = route.Create(set, mode, cacheDir);
            foreach (var c in cases)
            {
                var actual = eval.Evaluate(c.InputJson);
                var sameReasons = actual.Reasons.Order(StringComparer.Ordinal).SequenceEqual(c.ExpectedReasons.Order(StringComparer.Ordinal), StringComparer.Ordinal);
                var ok = string.Equals(actual.Outcome, c.Expected, StringComparison.Ordinal) && sameReasons;
                Console.WriteLine($"  [{route.Name}/{mode}] {c.Name}: expected {c.Expected}, got {actual.Outcome}{(ok ? "" : $"  <-- MISMATCH, reasons: {string.Join("; ", actual.Reasons)}")}");
                failures += ok ? 0 : 1;
            }
        }

        return failures;
    }

    public static int Expect(bool ok, string what)
    {
        Console.WriteLine($"  {(ok ? "ok  " : "FAIL")} {what}");
        return ok ? 0 : 1;
    }

    private static void CopyDirectory(string from, string to)
    {
        foreach (var dir in Directory.EnumerateDirectories(from, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, dir)));
        }

        Directory.CreateDirectory(to);
        foreach (var file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            File.Copy(file, Path.Combine(to, Path.GetRelativePath(from, file)));
        }
    }
}
