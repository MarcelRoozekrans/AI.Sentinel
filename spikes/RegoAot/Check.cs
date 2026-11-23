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
            failures += CheckBuiltins(route, set);
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

    private static readonly (string Kind, string Builtin)[] Probes =
    [
        ("probe-http", "http.send"),
        ("probe-dns", "net.lookup_ip_addr"),
        ("probe-runtime", "opa.runtime"),
    ];

    /// <summary>
    /// A bundle that calls builtins reaching outside the process must be refused when validated. A bundle
    /// that was not validated must deny at runtime, with a reason that names the builtin.
    /// </summary>
    private static int CheckBuiltins(IRoute route, BundleSet safe)
    {
        var failures = 0;
        failures += Expect(route.Validate(safe).Count == 0, $"[{route.Name}] the sample bundles pass validation");

        var tmp = Path.Combine(Path.GetTempPath(), "regoaot-unsafe-" + Guid.NewGuid().ToString("N"));
        try
        {
            CopyDirectory(safe.Root, tmp);
            CopyDirectory(Path.Combine(AppDir, "policy-unsafe"), tmp);
            var unsafeSet = BundleSet.Load(tmp);
            var refused = route.Validate(unsafeSet);
            foreach (var (_, builtin) in Probes)
            {
                failures += Expect(refused.Contains(builtin, StringComparer.Ordinal), $"[{route.Name}] validation refuses {builtin}");
            }

            foreach (var (kind, builtin) in Probes)
            {
                var decision = route.RunUnvalidated(unsafeSet, $"{{\"kind\":\"{kind}\",\"findings\":[],\"files\":[]}}");
                var named = decision.Reasons.Any(r => r.Contains(builtin, StringComparison.Ordinal));
                var denied = decision.Outcome == "deny" && named;
                if (!denied && route.RuntimeGaps.Contains(builtin, StringComparer.Ordinal))
                {
                    Console.WriteLine($"  gap  [{route.Name}] {builtin} is evaluated at runtime, got {decision.Outcome}; only validation keeps it out");
                    continue;
                }

                failures += Expect(denied, $"[{route.Name}] runtime call of {builtin} denies naming it ({string.Join("; ", decision.Reasons)})");
            }
        }
        finally
        {
            Directory.Delete(tmp, recursive: true);
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
