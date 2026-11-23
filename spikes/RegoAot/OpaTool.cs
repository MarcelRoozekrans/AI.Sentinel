using System.Diagnostics;
using System.Text;

namespace RegoAot;

/// <summary>The separate OPA binary. The spike downloads it, nothing in the repo ships it.</summary>
internal static class OpaTool
{
    private static string? _path;
    private static bool _searched;

    public static string? Path_
    {
        get
        {
            if (_searched)
            {
                return _path;
            }

            _searched = true;
            var env = Environment.GetEnvironmentVariable("OPA_BIN");
            if (!string.IsNullOrEmpty(env) && File.Exists(env))
            {
                return _path = env;
            }

            var exe = OperatingSystem.IsWindows() ? "opa.exe" : "opa";
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = System.IO.Path.Combine(dir, exe);
                if (File.Exists(candidate))
                {
                    return _path = candidate;
                }
            }

            return _path;
        }
    }

    public static string? Unavailable() => Path_ is null ? "no opa binary: set OPA_BIN or put opa on PATH" : null;

    public static (int Exit, string Out, string Err) Run(IEnumerable<string> args, string? stdin = null, string? workDir = null)
    {
        var psi = new ProcessStartInfo(Path_ ?? throw new InvalidOperationException("opa is not available"))
        {
            RedirectStandardInput = stdin is not null,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        if (workDir is not null)
        {
            psi.WorkingDirectory = workDir;
        }

        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("opa did not start");
        var err = p.StandardError.ReadToEndAsync();
        if (stdin is not null)
        {
            p.StandardInput.Write(stdin);
            p.StandardInput.Close();
        }

        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, output, err.GetAwaiter().GetResult());
    }
}
