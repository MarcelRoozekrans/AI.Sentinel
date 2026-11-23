using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace RegoAot;

/// <summary>Reads the decision object out of the JSON OPA prints, whatever wraps it.</summary>
internal static class OpaResult
{
    public static Decision Parse(JsonNode? node)
    {
        if (node is null)
        {
            return new Decision("defer", []);
        }

        var reasons = node["reasons"]!.AsArray().Select(n => n!.GetValue<string>()).ToList();
        return new Decision(node["outcome"]!.GetValue<string>(), reasons);
    }

    private static readonly Lazy<string> CapabilitiesFile = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "regoaot-caps-" + Guid.NewGuid().ToString("N"));
        Cache.Create(dir);
        var path = Path.Combine(dir, "capabilities.json");
        File.WriteAllText(path, OutsideBuiltins.Capabilities());
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Directory.Delete(dir, recursive: true);
        return path;
    });

    /// <summary>
    /// The capabilities document without the outside builtins, written once per process. Every opa command
    /// that loads the policy gets it, because without it OPA would run http.send for real.
    /// </summary>
    public static string[] CapabilitiesArgs() => ["--capabilities", CapabilitiesFile.Value];

    /// <summary>
    /// opa check with the capabilities document names the outside builtins as undefined functions, and
    /// opa eval with it fails the same way. A process cannot deny one call: the whole bundle fails to load.
    /// A failed check that names none of them is not a verdict on the builtins, so it is an error and the
    /// bundle is not accepted.
    /// </summary>
    public static IReadOnlyList<string> Validate(BundleSet set)
    {
        var (exit, output, err) = OpaTool.Run(["check", .. CapabilitiesArgs(), set.Root]);
        if (exit == 0)
        {
            return [];
        }

        var names = OutsideBuiltins.NamedIn(output + err);
        return names.Count > 0 ? names : throw new RegoCompileException((output + err).Trim());
    }

    public static Decision RunUnvalidated(BundleSet set, string inputJson)
    {
        var (exit, output, err) = OpaTool.Run(
            ["eval", .. CapabilitiesArgs(), "--stdin-input", "--format", "raw", "-d", set.Root, "data.sentinel.decision"],
            inputJson);
        if (exit == 0)
        {
            return Parse(JsonNode.Parse(output));
        }

        var names = OutsideBuiltins.NamedIn(output + err);
        return names.Count > 0
            ? new Decision("deny", [$"builtin {string.Join(", ", names)} reaches outside the process and is refused"])
            : throw new InvalidOperationException("opa failed: " + (output + err).Trim());
    }

    public static string BundlePath(BundleSet set, string cacheDir) => Path.Combine(cacheDir, set.Hash + ".tar.gz");

    public static void BuildBundle(BundleSet set, string cacheDir)
    {
        Cache.Create(cacheDir);
        var (exit, output, err) = OpaTool.Run(["build", .. CapabilitiesArgs(), "-o", BundlePath(set, cacheDir), set.Root]);
        if (exit != 0)
        {
            throw new RegoCompileException((output + err).Trim());
        }
    }
}

/// <summary>OPA as a short-lived process per call: opa eval, reading the input on stdin.</summary>
internal sealed class OpaEvalRoute : IRoute
{
    public string Name => "opa-eval";

    public IReadOnlyList<string> Modes => ["cached", "cold"];

    public string? Unavailable() => OpaTool.Unavailable();

    public void Prepare(BundleSet set, string cacheDir) => OpaResult.BuildBundle(set, cacheDir);

    public IReadOnlyList<string> RuntimeGaps => [];

    public IReadOnlyList<string> Validate(BundleSet set) => OpaResult.Validate(set);

    public Decision RunUnvalidated(BundleSet set, string inputJson) => OpaResult.RunUnvalidated(set, inputJson);

    public IEvaluator Create(BundleSet set, string mode, string cacheDir) =>
        new Evaluator(mode == "cold" ? ["-d", set.Root] : ["-b", OpaResult.BundlePath(set, cacheDir)]);

    private sealed class Evaluator(string[] source) : IEvaluator
    {
        public Decision Evaluate(string inputJson)
        {
            var args = new List<string> { "eval", "--stdin-input", "--format", "raw" };
            args.AddRange(OpaResult.CapabilitiesArgs());
            args.AddRange(source);
            args.Add("data.sentinel.decision");
            var (exit, output, err) = OpaTool.Run(args, stdin: inputJson);
            if (exit != 0)
            {
                throw new InvalidOperationException("opa eval failed: " + err.Trim());
            }

            return OpaResult.Parse(JsonNode.Parse(output));
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>OPA as a long-lived local server: opa run --server, queried over HTTP on the loopback interface.</summary>
internal sealed class OpaServerRoute : IRoute
{
    public string Name => "opa-server";

    public IReadOnlyList<string> Modes => ["cached", "cold", "warm"];

    public string? Unavailable() => OpaTool.Unavailable();

    public void Prepare(BundleSet set, string cacheDir) => OpaResult.BuildBundle(set, cacheDir);

    public IReadOnlyList<string> RuntimeGaps => [];

    public IReadOnlyList<string> Validate(BundleSet set) => OpaResult.Validate(set);

    /// <summary>
    /// opa run has no capabilities flag, so the server cannot refuse a builtin at runtime. The guard sits in front
    /// of it: Create validates a source directory before it starts the server, and the cached bundle was built
    /// with the capabilities document. Here the set is not validated, so Create refuses it and the call denies.
    /// </summary>
    public Decision RunUnvalidated(BundleSet set, string inputJson)
    {
        try
        {
            using var evaluator = Create(set, "cold", "");
            return evaluator.Evaluate(inputJson);
        }
        catch (RegoCompileException e) when (OutsideBuiltins.NamedIn(e.Message).Count > 0)
        {
            return new Decision("deny", [e.Message]);
        }
    }

    public IEvaluator Create(BundleSet set, string mode, string cacheDir)
    {
        if (mode != "cold")
        {
            return new Evaluator(OpaResult.BundlePath(set, cacheDir));
        }

        var refused = Validate(set);
        return refused.Count == 0
            ? new Evaluator(set.Root)
            : throw new RegoCompileException($"builtin {string.Join(", ", refused)} reaches outside the process and is refused");
    }

    private sealed class Evaluator : IEvaluator
    {
        private readonly Process _process;
        private readonly HttpClient _http;

        public Evaluator(string source)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

            var psi = new ProcessStartInfo(OpaTool.Path_!)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var a in (string[])["run", "--server", "--addr", $"127.0.0.1:{port}", "--log-level", "error", source])
            {
                psi.ArgumentList.Add(a);
            }

            _process = Process.Start(psi)!;
            _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/") };
            try
            {
                _process.OutputDataReceived += (_, _) => { };
                _process.BeginOutputReadLine();
                WaitUntilReady();
            }
            catch
            {
                // The constructor does not return, so nobody can dispose this: release the child and the client here.
                Dispose();
                throw;
            }
        }

        public Decision Evaluate(string inputJson)
        {
            using var content = new StringContent("{\"input\":" + inputJson + "}", Encoding.UTF8, "application/json");
            using var response = _http.PostAsync("v1/data/sentinel/decision", content).GetAwaiter().GetResult();
            response.EnsureSuccessStatusCode();
            var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return OpaResult.Parse(JsonNode.Parse(body)!["result"]);
        }

        private void WaitUntilReady()
        {
            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(10))
            {
                if (_process.HasExited)
                {
                    throw new InvalidOperationException("opa run exited with " + _process.ExitCode);
                }

                try
                {
                    using var response = _http.GetAsync("health").GetAwaiter().GetResult();
                    if (response.IsSuccessStatusCode)
                    {
                        return;
                    }
                }
                catch (HttpRequestException)
                {
                    // not listening yet
                }

                Thread.Sleep(1);
            }

            throw new TimeoutException("opa run did not become ready");
        }

        public void Dispose()
        {
            _http.Dispose();
            if (!_process.HasExited)
            {
                _process.Kill();
                _process.WaitForExit();
            }

            _process.Dispose();
        }
    }
}
