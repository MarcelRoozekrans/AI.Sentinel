---
sidebar_position: 1
title: Named pipelines
---

# Named pipelines

Register multiple isolated pipelines under string names; pick one per chat client at construction time. Useful for multi-LLM-endpoint apps and dev/staging/prod tier configurations.

```csharp
services.AddAISentinel(opts => opts.EmbeddingGenerator = realGen);
services.AddAISentinel("strict", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
});
services.AddAISentinel("lenient", opts =>
{
    opts.OnCritical = SentinelAction.Log;
    opts.Configure<RepetitionLoopDetector>(c => c.Enabled = false);
});

// Pick one per chat client
services.AddChatClient("openai-strict", b =>
    b.UseAISentinel("strict").Use(new OpenAIChatClient(...)));
```

Each named pipeline gets its own `SentinelOptions`, `IDetectionPipeline`, and `InterventionEngine`. Audit infrastructure is shared across all pipelines.

**Phase A limitations:**
- Always register the default unnamed `AddAISentinel(...)` first — shared infra is wired by it
- Tool-call authorization is global (named-pipeline `RequireToolPolicy` calls are silently ignored)
- No request-time selector yet — pipeline is fixed at chat-client construction

> Full named-pipelines guide — coming soon.
