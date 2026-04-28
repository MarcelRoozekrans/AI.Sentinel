using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detectors.Sdk;

/// <summary>
/// Fluent helper for unit-testing custom detectors. Configure a detector + prompt, then call one
/// of the <c>Expect*</c> terminals (or <see cref="RunAsync"/>) to invoke it and assert on the result.
/// </summary>
/// <remarks>
/// Defaults: a fresh <see cref="SentinelOptions"/> with a <see cref="FakeEmbeddingGenerator"/> pre-wired
/// (so semantic detectors work without API keys), and an empty <see cref="SentinelContextBuilder"/>.
/// One builder per test — not thread-safe, not designed for reuse across tests.
/// </remarks>
public sealed class DetectorTestBuilder
{
    private readonly SentinelOptions _options = new() { EmbeddingGenerator = new FakeEmbeddingGenerator() };
    private readonly SentinelContextBuilder _contextBuilder = new();
    private Func<SentinelOptions, IDetector>? _detectorResolver;

    /// <summary>Use a pre-constructed detector instance. Escape hatch for detectors with exotic constructors,
    /// DI-injected dependencies, or a custom <see cref="IEmbeddingGenerator{TInput, TEmbedding}"/>.</summary>
    public DetectorTestBuilder WithDetector(IDetector detector)
    {
        ArgumentNullException.ThrowIfNull(detector);
        _detectorResolver = _ => detector;
        return this;
    }

    /// <summary>Instantiate a detector with a parameterless constructor.
    /// Use the factory overload for detectors that take <see cref="SentinelOptions"/> or other dependencies.</summary>
    public DetectorTestBuilder WithDetector<T>() where T : class, IDetector, new()
    {
        _detectorResolver = _ => new T();
        return this;
    }

    /// <summary>Instantiate a detector via a user-supplied factory. The builder passes its internal
    /// <see cref="SentinelOptions"/> (with <see cref="FakeEmbeddingGenerator"/> pre-wired) so semantic
    /// detectors work out of the box.</summary>
    public DetectorTestBuilder WithDetector<T>(Func<SentinelOptions, T> factory) where T : class, IDetector
    {
        ArgumentNullException.ThrowIfNull(factory);
        _detectorResolver = opts => factory(opts);
        return this;
    }

    /// <summary>Mutate the internal <see cref="SentinelOptions"/> before the detector is constructed.
    /// Useful for swapping the embedding generator, attaching a cache, or tuning thresholds via options.
    /// Each call mutates the same options instance — multiple calls are additive.</summary>
    public DetectorTestBuilder WithOptions(Action<SentinelOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        configure(_options);
        return this;
    }

    /// <summary>Append a user-role message to the test context. Sugar for
    /// <c>WithContext(b =&gt; b.WithUserMessage(prompt))</c>.</summary>
    public DetectorTestBuilder WithPrompt(string prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        _contextBuilder.WithUserMessage(prompt);
        return this;
    }

    /// <summary>Configure the underlying <see cref="SentinelContextBuilder"/> directly. Use this for
    /// multi-message conversations, tool messages, history, or non-default sender/receiver/session IDs.
    /// Calls compose additively with <see cref="WithPrompt"/> in the order they are made.</summary>
    public DetectorTestBuilder WithContext(Action<SentinelContextBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        configure(_contextBuilder);
        return this;
    }

    /// <summary>Assert the detector fires with severity at or above <paramref name="minSeverity"/>.
    /// Throws <see cref="DetectorAssertionException"/> on mismatch. The most common assertion shape —
    /// most detectors guarantee "at least" a level, not exact equality.</summary>
    public async Task ExpectDetection(Severity minSeverity, CancellationToken ct = default)
    {
        var result = await RunAsync(ct).ConfigureAwait(false);
        if (result.Severity < minSeverity)
        {
            throw new DetectorAssertionException(
                $"Expected detector '{result.DetectorId.Value}' to fire with Severity >= {minSeverity} but got {DescribeObserved(result)}.");
        }
    }

    /// <summary>Assert the detector fires with exactly <paramref name="severity"/>. Stricter than
    /// <see cref="ExpectDetection"/> — useful for boundary tests where the difference between
    /// High and Critical matters.</summary>
    public async Task ExpectDetectionExactly(Severity severity, CancellationToken ct = default)
    {
        var result = await RunAsync(ct).ConfigureAwait(false);
        if (result.Severity != severity)
        {
            throw new DetectorAssertionException(
                $"Expected detector '{result.DetectorId.Value}' to fire with Severity == {severity} but got {DescribeObserved(result)}.");
        }
    }

    /// <summary>Assert the detector returns <see cref="DetectionResult.IsClean"/> (no detection).
    /// Distinct semantic from <c>ExpectDetectionExactly(Severity.None)</c> — clearer at the call site.</summary>
    public async Task ExpectClean(CancellationToken ct = default)
    {
        var result = await RunAsync(ct).ConfigureAwait(false);
        if (!result.IsClean)
        {
            throw new DetectorAssertionException(
                $"Expected detector '{result.DetectorId.Value}' to be Clean but got Severity.{result.Severity} — reason: '{result.Reason}'.");
        }
    }

    /// <summary>Invokes the detector and returns the raw <see cref="DetectionResult"/> for custom assertions.
    /// Use the <c>Expect*</c> terminals for the common cases.</summary>
    public async Task<DetectionResult> RunAsync(CancellationToken ct = default)
    {
        if (_detectorResolver is null)
        {
            throw new InvalidOperationException(
                "Call WithDetector<T>() or WithDetector(IDetector) before asserting.");
        }

        var detector = _detectorResolver(_options);
        var ctx = _contextBuilder.Build();
        return await detector.AnalyzeAsync(ctx, ct).ConfigureAwait(false);
    }

    private static string DescribeObserved(DetectionResult r)
        => r.IsClean ? $"Severity.{r.Severity} (Clean)" : $"Severity.{r.Severity}";
}
