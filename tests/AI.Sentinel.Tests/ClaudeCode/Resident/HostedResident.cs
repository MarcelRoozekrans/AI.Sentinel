using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>A resident host run inside the test process, so a test never leaves a background process behind.</summary>
internal sealed class HostedResident : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _listening = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public HostedResident(string stateDir, TimeSpan? idle = null, IReadOnlyList<AI.Sentinel.ClaudeCode.Policy.Rego.IRegoCompiler>? compilers = null)
    {
        Settings = new ResidentSettings(stateDir, idle ?? ResidentSettings.DefaultIdleTimeout, TimeSpan.FromMilliseconds(500));
        Run = Task.Run(() => ResidentHost.RunAsync(Settings, compilers, _stop.Token, () => _listening.TrySetResult()));
    }

    public ResidentSettings Settings { get; }

    /// <summary>The run of the host; its result says why it ended.</summary>
    public Task<ResidentExit> Run { get; }

    /// <summary>Completes when the host listens, or fails when it ended first.</summary>
    public async Task WaitUntilListeningAsync()
    {
        var first = await Task.WhenAny(_listening.Task, Run).WaitAsync(TimeSpan.FromSeconds(30));
        if (first == Run)
        {
            await Run;
            if (!_listening.Task.IsCompleted)
            {
                throw new InvalidOperationException("the host ended before it listened");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await Run.WaitAsync(TimeSpan.FromSeconds(30));
        }
        finally
        {
            _stop.Dispose();
        }
    }
}
