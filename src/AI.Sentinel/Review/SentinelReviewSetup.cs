using System.Globalization;
using AI.Sentinel.Http;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Review;

/// <summary>
/// Builds a second-stage reviewer from <c>SENTINEL_REVIEW_*</c> environment variables, for hosts that
/// have no other way to supply one.
/// </summary>
/// <remarks>
/// The hook CLIs, the MCP proxy and the scan CLI have no DI container to configure
/// <see cref="SentinelOptions.Reviewer"/>. Without this, a semantic hit there is capped at Medium
/// and never reviewed.
/// <para>
/// Recognised settings:
/// <list type="bullet">
/// <item><c>SENTINEL_REVIEW_ENDPOINT</c> — full chat completions URL. Required.</item>
/// <item><c>SENTINEL_REVIEW_MODEL</c> — model identifier. Required.</item>
/// <item><c>SENTINEL_REVIEW_API_KEY</c> — bearer token. Omit for local servers.</item>
/// <item><c>SENTINEL_REVIEW_MAX_PER_SCAN</c> — reviews per scan, 0 disables. Optional.</item>
/// <item><c>SENTINEL_REVIEW_TIMEOUT_MS</c> — per-review timeout in milliseconds. Optional.</item>
/// </list>
/// </para>
/// <para>
/// A malformed setting is reported by name rather than ignored.
/// </para>
/// </remarks>
public sealed class SentinelReviewSetup : IDisposable
{
    private const string EndpointKey = "SENTINEL_REVIEW_ENDPOINT";
    private const string ModelKey = "SENTINEL_REVIEW_MODEL";
    private const string ApiKeyKey = "SENTINEL_REVIEW_API_KEY";
    private const string MaxPerScanKey = "SENTINEL_REVIEW_MAX_PER_SCAN";
    private const string TimeoutKey = "SENTINEL_REVIEW_TIMEOUT_MS";

    private readonly OpenAICompatibleChatClient _client;

    private SentinelReviewSetup(
        OpenAICompatibleChatClient client, int? maxReviewsPerScan, TimeSpan? reviewTimeout)
    {
        _client = client;
        Reviewer = new LlmJudgeReviewer(client);
        MaxReviewsPerScan = maxReviewsPerScan;
        ReviewTimeout = reviewTimeout;
    }

    /// <summary>Assign to <see cref="SentinelOptions.Reviewer"/>.</summary>
    public IDetectionReviewer Reviewer { get; }

    /// <summary>When set, assign to <see cref="SentinelOptions.MaxReviewsPerScan"/>; otherwise keep the host default.</summary>
    public int? MaxReviewsPerScan { get; }

    /// <summary>When set, assign to <see cref="SentinelOptions.ReviewTimeout"/>; otherwise keep the host default.</summary>
    public TimeSpan? ReviewTimeout { get; }

    /// <summary>Reads the configuration, or returns <see langword="null"/>.</summary>
    /// <param name="environment">Environment variables to read.</param>
    /// <param name="configurationError">Set when the configuration is present but unusable. Hosts
    /// should surface this rather than leave the review quietly off.</param>
    public static SentinelReviewSetup? TryCreateFromEnvironment(
        IReadOnlyDictionary<string, string?> environment, out string? configurationError)
    {
        ArgumentNullException.ThrowIfNull(environment);
        configurationError = null;

        var endpointValue = Read(environment, EndpointKey);
        var modelValue = Read(environment, ModelKey);

        // Nothing configured at all is the documented default, not an error.
        if (endpointValue is null && modelValue is null) return null;

        if (endpointValue is null)
        {
            configurationError = $"AI.Sentinel: {ModelKey} is set but {EndpointKey} is missing — the second-stage review stays off.";
            return null;
        }

        if (modelValue is null)
        {
            configurationError = $"AI.Sentinel: {EndpointKey} is set but {ModelKey} is missing — the second-stage review stays off.";
            return null;
        }

        if (!SafeHttp.TryParseHttpEndpoint(endpointValue, out var endpoint))
        {
            configurationError = $"AI.Sentinel: {EndpointKey} is not an absolute http or https URL — the second-stage review stays off.";
            return null;
        }

        int? maxPerScan = null;
        var maxValue = Read(environment, MaxPerScanKey);
        if (maxValue is not null)
        {
            if (!int.TryParse(maxValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
            {
                configurationError = $"AI.Sentinel: {MaxPerScanKey} must be an integer of 0 or more ('{maxValue}') — the second-stage review stays off.";
                return null;
            }

            maxPerScan = parsed;
        }

        TimeSpan? timeout = null;
        var timeoutValue = Read(environment, TimeoutKey);
        if (timeoutValue is not null)
        {
            if (!int.TryParse(timeoutValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed <= 0)
            {
                configurationError = $"AI.Sentinel: {TimeoutKey} must be a positive integer number of milliseconds ('{timeoutValue}') — the second-stage review stays off.";
                return null;
            }

            timeout = TimeSpan.FromMilliseconds(parsed);
        }

        var client = new OpenAICompatibleChatClient(endpoint, modelValue, Read(environment, ApiKeyKey));
        return new SentinelReviewSetup(client, maxPerScan, timeout);
    }

    private static string? Read(IReadOnlyDictionary<string, string?> environment, string key) =>
        environment.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    /// <summary>Releases the chat client and its <see cref="HttpClient"/>.</summary>
    public void Dispose() => _client.Dispose();
}
