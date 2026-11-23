using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

/// <summary>A compiler that compiles nothing: it counts calls, tracks overlap, refuses the outside builtins as a restricted
/// compiler does, and lets a test act in the middle of a compile.</summary>
internal sealed class ScriptedCompiler : IRegoCompiler
{
    private int _calls;
    private int _running;
    private int _maxRunning;

    public string Name => "scripted";

    public int Calls => Volatile.Read(ref _calls);

    public int MaxRunning => Volatile.Read(ref _maxRunning);

    public string? UnavailableReason { get; set; }

    /// <summary>Runs during each compile, with the sources being compiled and the number of the call from 1.</summary>
    public Action<PolicySources, int>? OnCompile { get; set; }

    public PolicySources? Last { get; private set; }

    public string? Unavailable() => UnavailableReason;

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        var call = Interlocked.Increment(ref _calls);
        var running = Interlocked.Increment(ref _running);
        InterlockedMax(ref _maxRunning, running);
        try
        {
            Last = sources;
            OnCompile?.Invoke(sources, call);
            if (restrictBuiltins)
            {
                foreach (var file in sources.Files)
                {
                    var outside = OutsideBuiltins.NamedIn(file.Text);
                    if (outside.Count > 0)
                    {
                        throw RegoCompileException.From($"{file.Path}: rego_type_error: undefined function {outside[0]}");
                    }
                }
            }

            return [0];
        }
        finally
        {
            Interlocked.Decrement(ref _running);
        }
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int seen;
        do
        {
            seen = Volatile.Read(ref target);
        }
        while (value > seen && Interlocked.CompareExchange(ref target, value, seen) != seen);
    }
}
