using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using AI.Sentinel.Http;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Review;

/// <summary>
/// Minimal chat client for any endpoint speaking the OpenAI <c>/v1/chat/completions</c> shape.
/// </summary>
/// <remarks>
/// The bundled CLIs publish Native AOT and carry no chat provider, so the second-stage review would be
/// unavailable there. This client keeps it reachable without pulling a provider SDK into four AOT
/// binaries: it is plain <see cref="HttpClient"/> plus source-generated JSON, like
/// <c>OpenAICompatibleEmbeddingGenerator</c>.
/// <para>
/// Supply the full endpoint URL rather than a base address, since providers differ on the path.
/// Only what the reviewer needs is supported: text messages in, the first choice's text out, no
/// streaming. The answer must be a plain string <c>content</c>: a provider that returns an array of
/// content parts is rejected with <see cref="InvalidDataException"/>.
/// </para>
/// <para>
/// The owned <see cref="HttpClient"/> has a 30 second timeout as an outer bound. The review step's
/// <c>ReviewTimeout</c> cancels through the <see cref="CancellationToken"/> and normally fires first.
/// </para>
/// <para>
/// Error messages carry the status code and the endpoint's scheme, host, port and path only: never
/// the query string, userinfo or the response body, any of which can hold a key.
/// </para>
/// </remarks>
public sealed class OpenAICompatibleChatClient : IChatClient
{
    /// <summary>The most response bytes read from the endpoint: a verdict is a few hundred bytes.</summary>
    internal const int MaxResponseBytes = 1024 * 1024;

    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly Uri _endpoint;
    private readonly string _model;
    private readonly string? _apiKey;

    /// <param name="http">Client used for requests. Not disposed unless this instance created it.</param>
    /// <param name="endpoint">Full chat URL, e.g. <c>https://api.openai.com/v1/chat/completions</c>.</param>
    /// <param name="model">Model identifier sent with each request.</param>
    /// <param name="apiKey">Bearer token, or <see langword="null"/> for endpoints that need none.</param>
    public OpenAICompatibleChatClient(HttpClient http, Uri endpoint, string model, string? apiKey)
        : this(http, ownsClient: false, endpoint, model, apiKey)
    {
    }

    /// <summary>Creates a client owning its own <see cref="HttpClient"/>.</summary>
    public OpenAICompatibleChatClient(Uri endpoint, string model, string? apiKey)
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = MaxResponseBytes }, ownsClient: true, endpoint, model, apiKey)
    {
    }

    private OpenAICompatibleChatClient(HttpClient http, bool ownsClient, Uri endpoint, string model, string? apiKey)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);

        _http = http;
        _ownsClient = ownsClient;
        _endpoint = endpoint;
        _model = model;
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey;
    }

    /// <summary>Sends the messages and returns the first choice's text.</summary>
    /// <remarks><see cref="ChatOptions.ModelId"/> overrides the configured model for this call.
    /// <c>temperature</c> is sent only when <see cref="ChatOptions.Temperature"/> is set: some providers reject
    /// the field for some models, so a fixed default would fail every call to them.</remarks>
    public async Task<Microsoft.Extensions.AI.ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);

        var wire = messages.Select(m => new WireMessage(m.Role.Value, m.Text)).ToList();
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = JsonContent.Create(
                new CompletionRequest(options?.ModelId ?? _model, wire, options?.Temperature),
                ReviewJsonContext.Default.CompletionRequest),
        };

        if (_apiKey is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        }

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // HttpRequestException so callers get StatusCode, and because the review step counts any
            // exception as a failed review. The body is not read: providers echo masked keys in it.
            throw new HttpRequestException(
                $"Chat request to {SafeHttp.Describe(_endpoint)} failed with {(int)response.StatusCode} {response.ReasonPhrase}.",
                inner: null,
                response.StatusCode);
        }

        var payload = await SafeHttp
            .ReadJsonAsync(response.Content, ReviewJsonContext.Default.CompletionResponse, MaxResponseBytes, "Chat", cancellationToken)
            .ConfigureAwait(false);

        var content = payload?.Choices is { Count: > 0 } choices ? choices[0].Message?.Content : null;
        return content is null
            ? throw new InvalidDataException($"Chat endpoint {SafeHttp.Describe(_endpoint)} returned no choices[0].message.content.")
            : new Microsoft.Extensions.AI.ChatResponse(new ChatMessage(ChatRole.Assistant, content));
    }

    /// <inheritdoc />
    /// <exception cref="NotSupportedException">Always: the reviewer reads whole answers.</exception>
    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("OpenAICompatibleChatClient does not support streaming.");

    /// <inheritdoc />
    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        if (serviceKey is not null) return null;
        return serviceType.IsInstanceOfType(this) ? this : null;
    }

    /// <summary>Wire shapes for the OpenAI <c>/v1/chat/completions</c> contract.</summary>
    internal sealed record CompletionRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] IReadOnlyList<WireMessage> Messages,
        [property: JsonPropertyName("temperature")] float? Temperature);

    internal sealed record WireMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string? Content);

    internal sealed record CompletionResponse(
        [property: JsonPropertyName("choices")] IReadOnlyList<CompletionChoice>? Choices);

    internal sealed record CompletionChoice(
        [property: JsonPropertyName("message")] WireMessage? Message);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}
