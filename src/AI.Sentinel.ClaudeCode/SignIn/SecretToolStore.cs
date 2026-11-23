using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The Secret Service of Linux (GNOME Keyring, KWallet), through the <c>secret-tool</c> program: speaking D-Bus directly is too heavy for
/// a Native AOT hook. The secret goes to <c>secret-tool</c> on its standard input and comes back on its standard output, never as an
/// argument, so it is not visible in the process list. Where the program is missing, or there is no session bus or keyring, as on a
/// headless machine, every call fails and the token stays in memory.
/// </summary>
internal sealed class SecretToolStore(string account, Action<string>? log = null, string program = "secret-tool", TimeSpan? timeout = null) : ITokenStore
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    public string Name => "Linux Secret Service";

    public bool Save(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var result = Run(["store", "--label=AI.Sentinel sign-in", "service", "ai-sentinel", "account", account], secret);
        log?.Invoke(result.Started
            ? (result.ExitCode == 0 ? $"the refresh token is kept in the {Name} through {program}" : $"{program} did not take the refresh token (exit {result.ExitCode}); it is kept in memory only")
            : $"{program} is not available; the refresh token is kept in memory only");
        return result is { Started: true, ExitCode: 0 };
    }

    public string? Load()
    {
        var result = Run(["lookup", "service", "ai-sentinel", "account", account], stdin: null);
        return result is { Started: true, ExitCode: 0, Output.Length: > 0 } ? result.Output : null;
    }

    public bool Delete()
    {
        var result = Run(["clear", "service", "ai-sentinel", "account", account], stdin: null);
        // secret-tool clear exits 0 when nothing matched too, so any exit but a failure to start is fine only when it is 0.
        return result is { Started: true, ExitCode: 0 };
    }

    private (bool Started, int ExitCode, string Output) Run(string[] arguments, string? stdin)
    {
        var info = new ProcessStartInfo(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(info);
            if (process is null)
            {
                return (false, -1, string.Empty);
            }

            if (stdin is not null)
            {
                process.StandardInput.Write(stdin);
            }

            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeout ?? DefaultTimeout))
            {
                // A keyring that waits for the developer to unlock it must not hold a hook or the sign-in forever.
                process.Kill(entireProcessTree: true);
                return (true, -1, string.Empty);
            }

            return (true, process.ExitCode, output.GetAwaiter().GetResult());
        }
        catch (Exception e) when (e is Win32Exception or IOException or InvalidOperationException)
        {
            return (false, -1, string.Empty);
        }
    }
}
