using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// Compiles a policy in a child process that runs <see cref="PolicyCompileCommand"/>: by default the hook executable itself.
/// The compiler there is a Go library, and a crash of it ends only the child. The hook waits for the child with a timeout,
/// and reads the module from the output file only when its digest matches. A crash, a timeout, an exit code other than 0 or
/// an output that is missing or damaged throws, and the hook blocks the call: a crash in the hook process would be a
/// non-blocking error to Claude Code, which then runs the tool call.
/// </summary>
internal sealed class ChildProcessRegoCompiler : IRegoCompiler
{
    /// <summary>How long a compile may take. A policy compiles in well under a second; a child that takes this long hangs.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private readonly string _fileName;
    private readonly IReadOnlyList<string> _leadingArgs;
    private readonly string? _unavailable;
    private readonly TimeSpan _timeout;

    /// <param name="fileName">The program to start.</param>
    /// <param name="leadingArgs">The arguments before <see cref="PolicyCompileCommand.Verb"/> and its own.</param>
    /// <param name="unavailable">Why the child cannot compile here, or <see langword="null"/> when it can.</param>
    /// <param name="timeout">How long to wait for the child; <see cref="DefaultTimeout"/> when <see langword="null"/>.</param>
    public ChildProcessRegoCompiler(string fileName, IReadOnlyList<string> leadingArgs, string? unavailable = null, TimeSpan? timeout = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        ArgumentNullException.ThrowIfNull(leadingArgs);
        _fileName = fileName;
        _leadingArgs = leadingArgs;
        _unavailable = unavailable;
        _timeout = timeout ?? DefaultTimeout;
    }

    public string Name => "interop";

    /// <summary>The compiler of the running hook: this executable started again, as <c>dotnet &lt;assembly&gt;</c> when the
    /// hook runs on the <c>dotnet</c> host. It is unavailable where the build leaves the interop compiler out.</summary>
    public static ChildProcessRegoCompiler ForThisHook()
    {
        var unavailable = InteropRegoCompiler.Unavailable();
        var process = Environment.ProcessPath;
        if (string.IsNullOrEmpty(process))
        {
            return new ChildProcessRegoCompiler("sentinel-hook", [], unavailable ?? "the path of the hook executable is unknown");
        }

        return Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
            ? new ChildProcessRegoCompiler(process, [Environment.GetCommandLineArgs()[0]], unavailable)
            : new ChildProcessRegoCompiler(process, [], unavailable);
    }

    public string? Unavailable() => _unavailable;

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        ArgumentNullException.ThrowIfNull(sources);
        using var work = new TempFolder();
        var root = Path.Combine(work.Path, "policy");
        SourceFolder.Write(sources, root);
        var output = Path.Combine(work.Path, "policy.wasm");
        var psi = new ProcessStartInfo(_fileName)
        {
            // The hook's own stdout is its answer to the CLI, so the child never writes to it, and the child gets no stdin.
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in _leadingArgs)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.ArgumentList.Add(PolicyCompileCommand.Verb);
        psi.ArgumentList.Add(root);
        psi.ArgumentList.Add(output);
        if (!restrictBuiltins)
        {
            psi.ArgumentList.Add(PolicyCompileCommand.Unrestricted);
        }

        var (exit, stdout, stderr) = Run(psi);
        var message = (stderr + stdout).Trim();
        return exit switch
        {
            PolicyCompileCommand.Compiled => PolicyCache.TryRead(output)
                ?? throw new InvalidOperationException("the policy compiler process exited with code 0 but wrote no valid module"),
            PolicyCompileCommand.NotCompiled => throw new RegoCompileException(message),
            _ => throw new InvalidOperationException(
                $"the policy compiler process exited with code {exit}" + (message.Length > 0 ? ": " + message : string.Empty)),
        };
    }

    private (int Exit, string Stdout, string Stderr) Run(ProcessStartInfo psi)
    {
        Process process;
        try
        {
            process = Process.Start(psi) ?? throw new InvalidOperationException($"the policy compiler process {_fileName} did not start");
        }
        catch (Win32Exception e)
        {
            throw new InvalidOperationException($"the policy compiler process {_fileName} did not start: {e.Message}", e);
        }

        using (process)
        {
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(_timeout))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
                throw new TimeoutException($"the policy compiler process did not finish within {_timeout.TotalSeconds:0} s and was stopped");
            }

            // The exit is in; this waits for the output streams to close.
            process.WaitForExit();
            return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }
    }
}
