using System.Diagnostics;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>
/// The interop compiler run in a child process, see the project <c>AI.Sentinel.Tests.RegoCompiler</c>: the compiler is a Go
/// library, and a Go runtime loaded into the test host crashes tests that run after it. It compiles the policy folder it was
/// made for, counts how often it was asked to, and can be made to leave out the capabilities document.
/// </summary>
internal sealed class ChildProcessCompiler(string folder, bool unrestricted = false) : IRegoCompiler
{
    public int Compiles { get; private set; }

    public string Name => "child-process";

    public string? Unavailable() => null;

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        Compiles++;
        var helper = Path.Combine(AppContext.BaseDirectory, "AI.Sentinel.Tests.RegoCompiler.dll");
        if (!File.Exists(helper))
        {
            throw new FileNotFoundException($"compiler helper not found at {helper}");
        }

        var output = Path.Combine(Path.GetTempPath(), "sentinel-rego-" + Guid.NewGuid().ToString("N") + ".wasm");
        var psi = new ProcessStartInfo(DotnetHost()) { RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in new[] { "exec", helper, folder, output })
        {
            psi.ArgumentList.Add(arg);
        }

        if (unrestricted || !restrictBuiltins)
        {
            psi.ArgumentList.Add("--unrestricted");
        }

        try
        {
            using var process = Process.Start(psi)!;
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode switch
            {
                0 => File.ReadAllBytes(output),
                3 => throw new RegoCompileException(error.Trim()),
                var code => throw new InvalidOperationException($"the compiler helper exited with {code}: {error}"),
            };
        }
        finally
        {
            File.Delete(output);
        }
    }

    private static string DotnetHost()
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrEmpty(host) && File.Exists(host))
        {
            return host;
        }

        var current = Environment.ProcessPath;
        return current is not null && Path.GetFileNameWithoutExtension(current).Equals("dotnet", StringComparison.OrdinalIgnoreCase) ? current : "dotnet";
    }
}
