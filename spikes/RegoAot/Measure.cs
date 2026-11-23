using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace RegoAot;

/// <summary>
/// Decision time per call in three modes. Cold: a new process with no cache. Cached: a new process
/// with the module precompiled on disk. Warm: the same process, module and instance already loaded.
/// </summary>
internal static class Measure
{
    private const int WarmCalls = 1000;

    public static int Run(string[] args)
    {
        var runs = IntOption(args, "--runs", 200);
        var only = StringOption(args, "--routes");
        var set = BundleSet.Load(Path.Combine(Check.AppDir, "policy"));
        var cases = Cases.Load(Path.Combine(Check.AppDir, "inputs"));

        var routes = Routes.All().Where(r => only is null || only.Split(',').Contains(r.Name, StringComparer.Ordinal)).ToList();
        var rows = new List<Row>();
        foreach (var route in routes)
        {
            var why = route.Unavailable();
            if (why is not null)
            {
                Console.WriteLine($"route {route.Name}: unavailable ({why}), not measured");
                continue;
            }

            route.Prepare(set, Cache.Dir(set));
            foreach (var mode in route.Modes)
            {
                rows.Add(mode == "warm" ? MeasureWarm(route, set, cases) : MeasureSpawned(route, mode, runs));
            }
        }

        if (rows.Count == 0)
        {
            Console.WriteLine("no route is available, nothing was measured");
            return 0;
        }

        PrintTable(rows);
        PrintCompilers(set, runs);
        PrintSizes();
        return 0;
    }

    /// <summary>The child process of a cold or cached run: one evaluation, timed from loading the bundles.</summary>
    public static int Once(string[] args)
    {
        var routeName = args[Array.IndexOf(args, "--once") + 1];
        var mode = args[Array.IndexOf(args, "--once") + 2];
        var route = Routes.All().First(r => r.Name == routeName);
        var input = Cases.Load(Path.Combine(Check.AppDir, "inputs"))[0];

        var start = Stopwatch.GetTimestamp();
        var set = BundleSet.Load(Path.Combine(Check.AppDir, "policy"));
        using var eval = route.Create(set, mode, Cache.Dir(set));
        var decision = eval.Evaluate(input.InputJson);
        var micros = Stopwatch.GetElapsedTime(start).TotalMicroseconds;

        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{micros:F0} {decision.Outcome}"));
        return decision.Outcome == input.Expected ? 0 : 3;
    }

    private static Row MeasureSpawned(IRoute route, string mode, int runs)
    {
        var inProcess = new List<double>();
        var wall = new List<double>();
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("no process path");
        for (var i = 0; i < runs + 3; i++)
        {
            var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add("--once");
            psi.ArgumentList.Add(route.Name);
            psi.ArgumentList.Add(mode);
            var start = Stopwatch.GetTimestamp();
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            var elapsed = Stopwatch.GetElapsedTime(start).TotalMicroseconds;
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException($"{route.Name}/{mode} failed with {p.ExitCode}: {stdout} {stderr}");
            }

            if (i < 3)
            {
                continue; // the first runs warm the file cache of the machine, they are not the steady state
            }

            inProcess.Add(double.Parse(stdout.Split(' ')[0], CultureInfo.InvariantCulture));
            wall.Add(elapsed);
        }

        return new Row(route.Name, mode, inProcess, wall);
    }

    private static Row MeasureWarm(IRoute route, BundleSet set, List<Case> cases)
    {
        using var eval = route.Create(set, route.Modes.FirstOrDefault(m => m != "cold" && m != "warm") ?? "cold", Cache.Dir(set));
        for (var i = 0; i < 50; i++)
        {
            eval.Evaluate(cases[i % cases.Count].InputJson);
        }

        var times = new List<double>(WarmCalls);
        for (var i = 0; i < WarmCalls; i++)
        {
            var start = Stopwatch.GetTimestamp();
            eval.Evaluate(cases[i % cases.Count].InputJson);
            times.Add(Stopwatch.GetElapsedTime(start).TotalMicroseconds);
        }

        return new Row(route.Name, "warm", times, null);
    }

    private static void PrintTable(List<Row> rows)
    {
        var os = $"{Environment.OSVersion.Platform}/{System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}";
        Console.WriteLine($"platform: {os}, logical cores: {Environment.ProcessorCount}");
        Console.WriteLine("| route | mode | calls | p50 ms | p95 ms | max ms | process wall p50 ms | process wall p95 ms |");
        Console.WriteLine("|---|---|---|---|---|---|---|---|");
        foreach (var r in rows)
        {
            var sb = new StringBuilder();
            sb.Append(CultureInfo.InvariantCulture, $"| {r.Route} | {r.Mode} | {r.InProcess.Count} | {Ms(Percentile(r.InProcess, 50))} | {Ms(Percentile(r.InProcess, 95))} | {Ms(r.InProcess.Max())} |");
            sb.Append(r.Wall is null ? " n/a | n/a |" : $" {Ms(Percentile(r.Wall, 50))} | {Ms(Percentile(r.Wall, 95))} |");
            Console.WriteLine(sb.ToString());
        }
    }

    /// <summary>Compiling Rego to wasm: the first call of a process, then repeated calls.</summary>
    private static void PrintCompilers(BundleSet set, int runs)
    {
        Console.WriteLine();
        Console.WriteLine("| compiler | first call ms | p50 ms | p95 ms | calls |");
        Console.WriteLine("|---|---|---|---|---|");
        foreach (var compiler in Routes.Compilers())
        {
            var why = compiler.Unavailable();
            if (why is not null)
            {
                Console.WriteLine($"| {compiler.Name} | unavailable: {why} | | | |");
                continue;
            }

            var first = Stopwatch.GetTimestamp();
            compiler.CompileWasm(set);
            var firstMicros = Stopwatch.GetElapsedTime(first).TotalMicroseconds;
            var times = new List<double>();
            for (var i = 0; i < runs; i++)
            {
                var start = Stopwatch.GetTimestamp();
                compiler.CompileWasm(set);
                times.Add(Stopwatch.GetElapsedTime(start).TotalMicroseconds);
            }

            Console.WriteLine($"| {compiler.Name} | {Ms(firstMicros)} | {Ms(Percentile(times, 50))} | {Ms(Percentile(times, 95))} | {times.Count} |");
        }
    }

    private static void PrintSizes()
    {
        Console.WriteLine();
        Console.WriteLine("| file in the publish directory | MB |");
        Console.WriteLine("|---|---|");
        foreach (var file in new DirectoryInfo(Check.AppDir).EnumerateFiles().Where(f => !f.Name.EndsWith(".dbg", StringComparison.Ordinal)).OrderBy(f => f.Name, StringComparer.Ordinal))
        {
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"| {file.Name} | {file.Length / 1048576.0:F2} |"));
        }
    }

    private static string Ms(double micros) => (micros / 1000).ToString("F2", CultureInfo.InvariantCulture);

    /// <summary>Nearest-rank percentile.</summary>
    public static double Percentile(List<double> values, double percent)
    {
        var sorted = values.Order().ToList();
        var rank = (int)Math.Ceiling(percent / 100 * sorted.Count);
        return sorted[Math.Clamp(rank - 1, 0, sorted.Count - 1)];
    }

    private static int IntOption(string[] args, string name, int fallback)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 ? int.Parse(args[i + 1], CultureInfo.InvariantCulture) : fallback;
    }

    private static string? StringOption(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 ? args[i + 1] : null;
    }

    private sealed record Row(string Route, string Mode, List<double> InProcess, List<double>? Wall);
}
