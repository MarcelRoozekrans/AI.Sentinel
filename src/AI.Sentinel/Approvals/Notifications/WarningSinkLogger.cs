using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals.Notifications;

/// <summary>
/// The notifier's logger in a host with no logging stack, such as a CLI: warnings and worse go to a callback, such
/// as a stderr line, and nothing else is kept. No reflection and no logging provider, so it is AOT-safe.
/// </summary>
internal sealed class WarningSinkLogger(Action<string> sink) : ILogger<NotifyingApprovalStore>
{
    private readonly Action<string> _sink = sink ?? throw new ArgumentNullException(nameof(sink));

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

    public void Log<TState>(
        LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        if (IsEnabled(logLevel))
        {
            _sink(formatter(state, exception));
        }
    }
}
