using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using System.Net.Http.Json;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Embeddings;

/// <summary>
/// Minimal embedding client for any endpoint speaking the OpenAI <c>/v1/embeddings</c> shape.
/// </summary>
/// <remarks>
/// The bundled CLIs publish Native AOT and carry no embedding provider, which is why semantic
/// detection is unavailable there at all. This client keeps that reachable without pulling a provider
/// SDK into four AOT binaries: it is plain <see cref="HttpClient"/> plus source-generated JSON, the
/// same pattern as the webhook alert sink.
/// <para>
/// Because the wire format is the de-facto standard, it works against OpenAI, Azure OpenAI, and local
/// servers such as Ollama, LM Studio and vLLM. That matters for a hook: a developer should not need a
/// cloud API key before prompt-injection detection will run at all.
/// </para>
/// <para>
/// Supply the full endpoint URL rather than a base address, since providers differ on the path —
/// Azure OpenAI in particular uses a deployment-scoped URL.
/// </para>
/// </remarks>
public sealed class OpenAICompatibleEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly Uri _endpoint;
    private readonly string _model;
    private readonly string? _apiKey;
    private readonly int? _dimensions;

    /// <param name="http">Client used for requests. Not disposed unless this instance created it.</param>
    /// <param name="endpoint">Full embeddings URL, e.g. <c>https://api.openai.com/v1/embeddings</c>.</param>
    /// <param name="model">Model identifier sent with each request.</param>
    /// <param name="apiKey">Bearer token, or <see langword="null"/> for endpoints that need none.</param>
    /// <param name="dimensions">Vector length the model produces, when known. Reported through
    /// <see cref="Metadata"/> so a persistent cache can bind entries to it.</param>
    public OpenAICompatibleEmbeddingGenerator(
        HttpClient http, Uri endpoint, string model, string? apiKey, int? dimensions = null)
        : this(http, ownsClient: false, endpoint, model, apiKey, dimensions)
    {
    }

    /// <summary>Creates a generator owning its own <see cref="HttpClient"/>.</summary>
    public OpenAICompatibleEmbeddingGenerator(Uri endpoint, string model, string? apiKey, int? dimensions = null)
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) }, ownsClient: true, endpoint, model, apiKey, dimensions)
    {
    }

    private OpenAICompatibleEmbeddingGenerator(
        HttpClient http, bool ownsClient, Uri endpoint, string model, string? apiKey, int? dimensions)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);

        _http = http;
        _ownsClient = ownsClient;
        _endpoint = endpoint;
        _model = model;
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey;
        _dimensions = dimensions;

        Metadata = new EmbeddingGeneratorMetadata(
            providerName: "openai-compatible",
            providerUri: endpoint,
            defaultModelId: model,
            defaultModelDimensions: dimensions);
    }

    /// <inheritdoc />
    public EmbeddingGeneratorMetadata Metadata { get; }

    /// <inheritdoc />
    public async Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
        IEnumerable<string> values,
        EmbeddingGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(values);

        var inputs = values as IReadOnlyList<string> ?? [.. values];
        if (inputs.Count == 0) return new GeneratedEmbeddings<Embedding<float>>();

        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = JsonContent.Create(
                new EmbeddingRequest(inputs, options?.ModelId ?? _model, options?.Dimensions ?? _dimensions),
                EmbeddingJsonContext.Default.EmbeddingRequest),
        };

        if (_apiKey is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        }

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var detail = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException(
                $"Embedding request to {_endpoint} failed with {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(detail)}");
        }

        var payload = await response.Content
            .ReadFromJsonAsync(EmbeddingJsonContext.Default.EmbeddingResponse, cancellationToken)
            .ConfigureAwait(false);

        return Materialise(payload, inputs.Count);
    }

    private GeneratedEmbeddings<Embedding<float>> Materialise(EmbeddingResponse? payload, int expected)
    {
        var data = payload?.Data;
        if (data is null || data.Count != expected)
        {
            // A short or padded result would pair vectors with the wrong inputs — and with a persistent
            // cache, store them under the wrong keys.
            throw new InvalidOperationException(
                $"Embedding endpoint {_endpoint} returned {data?.Count ?? 0} vectors for {expected} inputs.");
        }

        var ordered = new float[expected][];
        foreach (var item in data)
        {
            // The index field is authoritative: providers may return results out of order.
            if (item.Index < 0 || item.Index >= expected || ordered[item.Index] is not null)
            {
                throw new InvalidOperationException(
                    $"Embedding endpoint {_endpoint} returned an invalid or duplicate index {item.Index}.");
            }

            ordered[item.Index] = item.Embedding ?? throw new InvalidOperationException(
                $"Embedding endpoint {_endpoint} returned an entry with no vector.");
        }

        var result = new GeneratedEmbeddings<Embedding<float>>(expected);
        foreach (var vector in ordered)
        {
            // A provider that ignores the requested length must fail here. The persistent cache binds
            // its file to the configured dimension, so a wrong-sized vector would write a header that
            // contradicts its own entries — and every later process would reject the file as corrupt
            // and re-embed everything, silently and forever.
            if (_dimensions is { } expectedLength && vector.Length != expectedLength)
            {
                throw new InvalidOperationException(
                    $"Embedding endpoint {_endpoint} returned a vector of dimension {vector.Length}, but {expectedLength} was requested.");
            }

            result.Add(new Embedding<float>(vector));
        }

        return result;
    }

    private static string Truncate(string value) =>
        value.Length <= 256 ? value : value[..256];

    /// <inheritdoc />
    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        if (serviceKey is not null) return null;
        if (serviceType == typeof(EmbeddingGeneratorMetadata)) return Metadata;
        return serviceType.IsInstanceOfType(this) ? this : null;
    }

    /// <summary>Wire shapes for the OpenAI <c>/v1/embeddings</c> contract.</summary>
    internal sealed record EmbeddingRequest(
        [property: JsonPropertyName("input")] IReadOnlyList<string> Input,
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("dimensions")] int? Dimensions);

    internal sealed record EmbeddingResponse(
        [property: JsonPropertyName("data")] IReadOnlyList<EmbeddingDatum>? Data);

    internal sealed record EmbeddingDatum(
        [property: JsonPropertyName("index")] int Index,
        [property: JsonPropertyName("embedding")] float[]? Embedding);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}
