using System.Text.Json;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>Builds a real tool call guard from an approval config whose Bash rule has a <c>when</c> condition.</summary>
internal static class ApprovalRuleGuard
{
    private const string BashWhenConfig = """
        {
            "backend": "in-memory",
            "tools": { "Bash": [ { "role": "Ops", "when": { "$.command": "kubectl\\s+delete" } } ] }
        }
        """;

    /// <summary>Requires approval for Bash calls whose command matches <c>kubectl delete</c>.</summary>
    public static IToolCallGuard BuildBashWhen(out ServiceProvider provider)
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.OnCritical = SentinelAction.Quarantine;
            o.OnHigh = SentinelAction.Quarantine;
            o.OnMedium = SentinelAction.Quarantine;
            o.OnLow = SentinelAction.Quarantine;
            o.EmbeddingGenerator = new FakeEmbeddingGenerator();
            using var doc = JsonDocument.Parse(BashWhenConfig);
            ApprovalBackendSelector.Configure(o, ApprovalConfigLoader.Parse(doc.RootElement));
        });
        provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IToolCallGuard>();
    }
}
