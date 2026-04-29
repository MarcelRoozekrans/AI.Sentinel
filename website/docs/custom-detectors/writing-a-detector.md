---
sidebar_position: 2
title: Writing a detector
---

# Writing a detector

```csharp
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

public sealed class HelloWorldDetector : IDetector
{
    private static readonly DetectorId _id = new("MYORG-01");
    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        return ctx.TextContent.Contains("hello", StringComparison.OrdinalIgnoreCase)
            ? ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low, "Greeting detected"))
            : ValueTask.FromResult(DetectionResult.Clean(_id));
    }
}
```

**Detector ID convention.** Prefix your detector ID with a vendor/org tag to avoid collisions with future official detectors (which use `SEC-`, `HAL-`, `OPS-`). Examples: `ACME-01`, `MYORG-CUSTOM-01`.

Register it:

```csharp
services.AddAISentinel(opts =>
{
    opts.AddDetector<HelloWorldDetector>();

    // Factory overload for detectors needing custom DI:
    opts.AddDetector(sp => new TenantAwareDetector(sp.GetRequiredService<IHttpClientFactory>()));
});
```

> Full guide — semantic detectors via `SemanticDetectorBase`, LLM-escalating detectors via `ILlmEscalatingDetector`, severity guidance — coming soon.
