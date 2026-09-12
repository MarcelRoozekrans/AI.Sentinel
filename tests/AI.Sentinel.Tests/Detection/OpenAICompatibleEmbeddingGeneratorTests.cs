using System.Net;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Embeddings;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>The CLIs carry no embedding provider, so semantic detection is unavailable there
/// entirely. This client is what makes it reachable — against OpenAI, Azure OpenAI, or a local
/// Ollama / LM Studio endpoint, which matters because a hook user should not need a cloud key to
/// get prompt-injection detection.</summary>
public class OpenAICompatibleEmbeddingGeneratorTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequest = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return respond(request);
        }
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static string EmbeddingsResponse(params float[][] vectors)
    {
        var items = vectors.Select((v, i) =>
            $$"""{"object":"embedding","index":{{i}},"embedding":[{{string.Join(",", v.Select(f => f.ToString(System.Globalization.CultureInfo.InvariantCulture)))}}]}""");
        return $$"""{"object":"list","data":[{{string.Join(",", items)}}],"model":"m"}""";
    }

    [Fact]
    public async Task GenerateAsync_ReturnsOneVectorPerInput_InOrder()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f, 2f], [3f, 4f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "test-model", apiKey: null);

        var result = await generator.GenerateAsync(["first", "second"], null, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Count);
        Assert.Equal(new[] { 1f, 2f }, result[0].Vector.ToArray());
        Assert.Equal(new[] { 3f, 4f }, result[1].Vector.ToArray());
    }

    /// <summary>Providers are permitted to return results out of order; the index field is
    /// authoritative. Trusting array position would pair vectors with the wrong phrases and, with a
    /// persistent cache, store them under the wrong keys.</summary>
    [Fact]
    public async Task GenerateAsync_HonoursTheIndexField_NotArrayPosition()
    {
        const string body = """
            {"object":"list","data":[
              {"object":"embedding","index":1,"embedding":[9,9]},
              {"object":"embedding","index":0,"embedding":[1,1]}
            ],"model":"m"}
            """;
        var handler = new StubHandler(_ => Json(body));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: null);

        var result = await generator.GenerateAsync(["zero", "one"], null, TestContext.Current.CancellationToken);

        Assert.Equal(new[] { 1f, 1f }, result[0].Vector.ToArray());
        Assert.Equal(new[] { 9f, 9f }, result[1].Vector.ToArray());
    }

    [Fact]
    public async Task GenerateAsync_SendsModelAndInputs()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "text-embedding-3-small", apiKey: null);

        await generator.GenerateAsync(["hello"], null, TestContext.Current.CancellationToken);

        using var sent = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal("text-embedding-3-small", sent.RootElement.GetProperty("model").GetString());
        Assert.Equal("hello", sent.RootElement.GetProperty("input")[0].GetString());
    }

    [Fact]
    public async Task GenerateAsync_SendsBearerToken_WhenAnApiKeyIsSupplied()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: "sk-secret");

        await generator.GenerateAsync(["hello"], null, TestContext.Current.CancellationToken);

        Assert.Equal("Bearer", handler.LastRequest!.Headers.Authorization!.Scheme);
        Assert.Equal("sk-secret", handler.LastRequest.Headers.Authorization.Parameter);
    }

    /// <summary>A local endpoint needs no key, and requiring one would block Ollama / LM Studio.</summary>
    [Fact]
    public async Task GenerateAsync_SendsNoAuthorization_WhenNoApiKey()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("http://localhost:11434/v1/embeddings"), "nomic-embed-text", apiKey: null);

        await generator.GenerateAsync(["hello"], null, TestContext.Current.CancellationToken);

        Assert.Null(handler.LastRequest!.Headers.Authorization);
    }

    /// <summary>A silent partial result would pair vectors with the wrong phrases; SemanticDetectorBase
    /// guards this too, but the client should not produce it in the first place.</summary>
    [Fact]
    public async Task GenerateAsync_Throws_WhenTheProviderReturnsFewerVectorsThanInputs()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: null);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await generator.GenerateAsync(["a", "b"], null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GenerateAsync_Throws_OnAnErrorStatus()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("""{"error":{"message":"bad key"}}""", Encoding.UTF8, "application/json"),
        });
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: "nope");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await generator.GenerateAsync(["a"], null, TestContext.Current.CancellationToken));

        Assert.Contains("401", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Metadata_CarriesTheModelAndDimensions()
    {
        using var client = new HttpClient(new StubHandler(_ => Json(EmbeddingsResponse([1f]))));
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "text-embedding-3-small", apiKey: null, dimensions: 1536);

        Assert.Equal("text-embedding-3-small", generator.Metadata.DefaultModelId);
        Assert.Equal(1536, generator.Metadata.DefaultModelDimensions);
    }

    /// <summary>Configured dimensions must be sent, not merely reported in metadata. The persistent
    /// cache binds its file to the configured value, so a provider returning its default length
    /// instead writes a header that contradicts its own entries — and every later process rejects the
    /// file as corrupt and re-embeds all 82 phrases, forever, silently.</summary>
    [Fact]
    public async Task GenerateAsync_SendsConfiguredDimensions_WhenTheCallerSuppliesNoOptions()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f, 2f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: null, dimensions: 2);

        await generator.GenerateAsync(["hello"], null, TestContext.Current.CancellationToken);

        using var sent = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal(2, sent.RootElement.GetProperty("dimensions").GetInt32());
    }

    /// <summary>If the provider ignores the requested length, fail here rather than let a vector of
    /// the wrong size poison the cache.</summary>
    [Fact]
    public async Task GenerateAsync_Throws_WhenAVectorLengthContradictsTheConfiguredDimensions()
    {
        var handler = new StubHandler(_ => Json(EmbeddingsResponse([1f, 2f, 3f])));
        using var client = new HttpClient(handler);
        using var generator = new OpenAICompatibleEmbeddingGenerator(
            client, new Uri("https://example.invalid/v1/embeddings"), "m", apiKey: null, dimensions: 2);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await generator.GenerateAsync(["hello"], null, TestContext.Current.CancellationToken));

        Assert.Contains("dimension", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
