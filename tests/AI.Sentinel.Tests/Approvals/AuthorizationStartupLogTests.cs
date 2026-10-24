using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AI.Sentinel.Tests.Approvals;

/// <summary>The startup checks logged when the tool-call guard is first resolved.</summary>
public class AuthorizationStartupLogTests
{
    private sealed class CapturingLogger : ILogger<SentinelPipeline>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    private static CapturingLogger ResolveGuard(Action<SentinelOptions> configure)
    {
        var logger = new CapturingLogger();
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new FakeEmbeddingGenerator();
            configure(o);
        });
        services.AddSingleton<ILogger<SentinelPipeline>>(logger);
        using var provider = services.BuildServiceProvider();
        _ = provider.GetRequiredService<IToolCallGuard>();
        return logger;
    }

    [Fact]
    public void ApprovalBinding_DoesNotLogUnknownPolicy()
    {
        var logger = ResolveGuard(o => o.RequireApproval("Bash", spec => spec.WhenArgument("$.command", "delete")));

        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("unknown policy", StringComparison.Ordinal));
    }

    [Fact]
    public void PolicyBinding_WithUnknownPolicy_LogsError()
    {
        var logger = ResolveGuard(o => o.RequireToolPolicy("Bash", "no-such-policy"));

        var error = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Contains("unknown policy 'no-such-policy'", error.Message, StringComparison.Ordinal);
    }
}
