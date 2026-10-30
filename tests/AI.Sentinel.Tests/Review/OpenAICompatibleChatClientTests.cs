using System.Net;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Review;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Review;

/// <summary>The CLIs carry no chat provider, so the second-stage review is unavailable there without
/// this client. It speaks the OpenAI chat-completions shape, which OpenAI, Azure OpenAI and local
/// servers share.</summary>
public class OpenAICompatibleChatClientTests
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

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private const string Reply = """{"choices":[{"index":0,"message":{"role":"assistant","content":"hello back"}}]}""";

    private static readonly Uri Endpoint = new("https://example.invalid/v1/chat/completions");

    private static List<ChatMessage> Messages() =>
        [new(ChatRole.System, "be strict"), new(ChatRole.User, "judge this")];

    [Fact]
    public async Task GetResponseAsync_SendsModelMessagesAndZeroTemperature()
    {
        var handler = new StubHandler(_ => Json(Reply));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "judge-model", apiKey: null);

        await client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken);

        using var sent = JsonDocument.Parse(handler.LastBody!);
        var root = sent.RootElement;
        Assert.Equal("judge-model", root.GetProperty("model").GetString());
        Assert.Equal(0, root.GetProperty("temperature").GetDouble());
        var messages = root.GetProperty("messages");
        Assert.Equal(2, messages.GetArrayLength());
        Assert.Equal("system", messages[0].GetProperty("role").GetString());
        Assert.Equal("be strict", messages[0].GetProperty("content").GetString());
        Assert.Equal("user", messages[1].GetProperty("role").GetString());
        Assert.Equal("judge this", messages[1].GetProperty("content").GetString());
        Assert.Equal(Endpoint, handler.LastRequest!.RequestUri);
    }

    [Fact]
    public async Task GetResponseAsync_SendsBearerKey_WhenConfigured()
    {
        var handler = new StubHandler(_ => Json(Reply));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: "sk-test");

        await client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("Bearer", handler.LastRequest!.Headers.Authorization!.Scheme);
        Assert.Equal("sk-test", handler.LastRequest.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task GetResponseAsync_SendsNoAuthorizationHeader_WithoutAKey()
    {
        var handler = new StubHandler(_ => Json(Reply));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        await client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(handler.LastRequest!.Headers.Authorization);
    }

    [Fact]
    public async Task GetResponseAsync_ReturnsTheFirstChoiceContent()
    {
        var handler = new StubHandler(_ => Json(Reply));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        var response = await client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("hello back", response.Text);
    }

    [Fact]
    public async Task GetResponseAsync_NonSuccess_ThrowsHttpRequestExceptionWithTheStatus()
    {
        var handler = new StubHandler(_ => Json("""{"error":"nope"}""", HttpStatusCode.Unauthorized));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("401", ex.Message);
    }

    [Theory]
    [InlineData("""{"object":"chat.completion"}""")]
    [InlineData("""{"choices":[]}""")]
    [InlineData("""{"choices":[{"message":{"role":"assistant"}}]}""")]
    public async Task GetResponseAsync_MissingChoices_ThrowsInvalidData(string body)
    {
        var handler = new StubHandler(_ => Json(body));
        using var http = new HttpClient(handler);
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => client.GetResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void GetStreamingResponseAsync_IsNotSupported()
    {
        using var http = new HttpClient(new StubHandler(_ => Json(Reply)));
        using var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        Assert.Throws<NotSupportedException>(() => client.GetStreamingResponseAsync(Messages(), cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Dispose_LeavesACallerSuppliedClientUsable()
    {
        using var http = new HttpClient(new StubHandler(_ => Json(Reply)));
        var client = new OpenAICompatibleChatClient(http, Endpoint, "m", apiKey: null);

        client.Dispose();

        // Would throw ObjectDisposedException had the client been disposed.
        _ = http.BaseAddress;
        http.DefaultRequestHeaders.Add("x-probe", "1");
    }
}
