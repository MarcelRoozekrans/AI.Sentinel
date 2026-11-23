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

    public static string BundlePath(BundleSet set, string cacheDir) => Path.Combine(cacheDir, set.Hash + ".tar.gz");

    public static void BuildBundle(BundleSet set, string cacheDir)
    {
        Directory.CreateDirectory(cacheDir);
        var (exit, _, err) = OpaTool.Run(["build", "-o", BundlePath(set, cacheDir), set.Root]);
        if (exit != 0)
        {
            throw new RegoCompileException(err.Trim());
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

    public IEvaluator Create(BundleSet set, string mode, string cacheDir) =>
        new Evaluator(mode == "cold" ? ["-d", set.Root] : ["-b", OpaResult.BundlePath(set, cacheDir)]);

    private sealed class Evaluator(string[] source) : IEvaluator
    {
        public Decision Evaluate(string inputJson)
        {
            var args = new List<string> { "eval", "--stdin-input", "--format", "raw" };
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

    public IEvaluator Create(BundleSet set, string mode, string cacheDir) =>
        new Evaluator(mode == "cold" ? set.Root : OpaResult.BundlePath(set, cacheDir));

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
            foreach (var a in new[] { "run", "--server", "--addr", $"127.0.0.1:{port}", "--log-level", "error", source })
            {
                psi.ArgumentList.Add(a);
            }

            _process = Process.Start(psi)!;
            _process.OutputDataReceived += (_, _) => { };
            _process.BeginOutputReadLine();
            _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/") };
            WaitUntilReady();
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
