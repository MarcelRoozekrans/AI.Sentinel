using System.Globalization;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Embeddings;

/// <summary>
/// Builds an embedding generator and its persistent example cache from <c>SENTINEL_EMBEDDING_*</c>
/// environment variables, for hosts that have no other way to supply one.
/// </summary>
/// <remarks>
/// The bundled CLIs could not configure an embedding generator at all, so every semantic detector —
/// SEC-01 PromptInjection and SEC-05 Jailbreak among them — returned Clean in the integration
/// recommended for coding agents. This is the switch that turns them on.
/// <para>
/// Recognised settings:
/// <list type="bullet">
/// <item><c>SENTINEL_EMBEDDING_ENDPOINT</c> — full embeddings URL. Required.</item>
/// <item><c>SENTINEL_EMBEDDING_MODEL</c> — model identifier. Required.</item>
/// <item><c>SENTINEL_EMBEDDING_API_KEY</c> — bearer token. Omit for local servers.</item>
/// <item><c>SENTINEL_EMBEDDING_DIMENSIONS</c> — vector length, when the model allows a choice.</item>
/// <item><c>SENTINEL_EMBEDDING_CACHE_DIR</c> — overrides <see cref="DefaultCacheDirectory"/>.</item>
/// </list>
/// </para>
/// <para>
/// A malformed setting is reported by name rather than ignored. Leaving detection quietly off because
/// of a typo is the failure this whole feature exists to remove.
/// </para>
/// </remarks>
public sealed class SentinelEmbeddingSetup : IDisposable
{
    private const string EndpointKey = "SENTINEL_EMBEDDING_ENDPOINT";
    private const string ModelKey = "SENTINEL_EMBEDDING_MODEL";
    private const string ApiKeyKey = "SENTINEL_EMBEDDING_API_KEY";
    private const string DimensionsKey = "SENTINEL_EMBEDDING_DIMENSIONS";
    private const string CacheDirKey = "SENTINEL_EMBEDDING_CACHE_DIR";

    private readonly OpenAICompatibleEmbeddingGenerator _generator;
    private readonly FileSystemEmbeddingCache _cache;

    private SentinelEmbeddingSetup(OpenAICompatibleEmbeddingGenerator generator, FileSystemEmbeddingCache cache)
    {
        _generator = generator;
        _cache = cache;
    }

    /// <summary>Assign to <see cref="SentinelOptions.EmbeddingGenerator"/>.</summary>
    public IEmbeddingGenerator<string, Embedding<float>> Generator => _generator;

    /// <summary>Assign to <see cref="SentinelOptions.ExampleEmbeddingCache"/>. Without it a
    /// per-invocation host re-embeds every detector's example phrases on every run.</summary>
    public IEmbeddingCache ExampleCache => _cache;

    /// <summary>Per-user cache location. The cache file is unauthenticated, so a shared directory
    /// would let anyone who can write it replace the reference vectors with noise and silently
    /// disable semantic detection — never default to a world-writable temp path.</summary>
    public static string DefaultCacheDirectory
    {
        get
        {
            var root = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
            if (string.IsNullOrWhiteSpace(root))
            {
                root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            }

            if (string.IsNullOrWhiteSpace(root))
            {
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                root = Path.Combine(home, ".cache");
            }

            return Path.Combine(root, "ai-sentinel", "embeddings");
        }
    }

    /// <summary>Reads the configuration, or returns <see langword="null"/>.</summary>
    /// <param name="environment">Environment variables to read.</param>
    /// <param name="configurationError">Set when the configuration is present but unusable. Hosts
    /// should surface this — a silent return would reproduce the bug this feature fixes.</param>
    public static SentinelEmbeddingSetup? TryCreateFromEnvironment(
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
            configurationError = $"AI.Sentinel: {ModelKey} is set but {EndpointKey} is missing — semantic detection stays off.";
            return null;
        }

        if (modelValue is null)
        {
            configurationError = $"AI.Sentinel: {EndpointKey} is set but {ModelKey} is missing — semantic detection stays off.";
            return null;
        }

        if (!Uri.TryCreate(endpointValue, UriKind.Absolute, out var endpoint))
        {
            configurationError = $"AI.Sentinel: {EndpointKey} is not an absolute URL ('{endpointValue}') — semantic detection stays off.";
            return null;
        }

        int? dimensions = null;
        var dimensionsValue = Read(environment, DimensionsKey);
        if (dimensionsValue is not null)
        {
            if (!int.TryParse(dimensionsValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed <= 0)
            {
                configurationError = $"AI.Sentinel: {DimensionsKey} must be a positive integer ('{dimensionsValue}') — semantic detection stays off.";
                return null;
            }

            dimensions = parsed;
        }

        var cacheDirectory = Read(environment, CacheDirKey) ?? DefaultCacheDirectory;

        OpenAICompatibleEmbeddingGenerator? generator = null;
        try
        {
            generator = new OpenAICompatibleEmbeddingGenerator(endpoint, modelValue, Read(environment, ApiKeyKey), dimensions);
            var cache = new FileSystemEmbeddingCache(cacheDirectory, modelValue, dimensions);
            return new SentinelEmbeddingSetup(generator, cache);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            generator?.Dispose();
            configurationError = $"AI.Sentinel: embedding cache directory '{cacheDirectory}' is unusable ({ex.Message}) — semantic detection stays off.";
            return null;
        }
    }

    private static string? Read(IReadOnlyDictionary<string, string?> environment, string key) =>
        environment.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    /// <summary>Flushes the cache, then releases the generator. Hosts must dispose this or the example
    /// vectors never reach disk and every run stays cold.</summary>
    public void Dispose()
    {
        _cache.Dispose();
        _generator.Dispose();
    }
}
