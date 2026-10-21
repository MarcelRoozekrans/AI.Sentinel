using System.Text.Json;
using System.Text.RegularExpressions;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class HostRedactionTests
{
    private const string Email = "jan@example.com";
    private const string ApiKey = "api_key=sk-test-0123456789abcdefghij";

    private sealed class NeverCalledClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The host redaction path never calls the model.");

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The host redaction path never calls the model.");

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose()
        {
        }
    }

    private sealed class ThrowingRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-THROW");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) =>
            throw new RegexMatchTimeoutException(text, "pattern", TimeSpan.FromSeconds(1));
    }

    private static (SentinelPipeline Pipeline, IAuditStore Audit) Build(Action<SentinelOptions>? configure = null)
    {
        var provider = new ServiceCollection().AddAISentinel(o =>
        {
            o.OnMedium = SentinelAction.Quarantine;
            o.OnHigh = SentinelAction.Quarantine;
            o.OnCritical = SentinelAction.Quarantine;
            configure?.Invoke(o);
        }).BuildServiceProvider();
        return (provider.BuildSentinelPipeline(new NeverCalledClient()), provider.GetRequiredService<IAuditStore>());
    }

    private static ValueTask<HostRedactionResult> RunAsync(SentinelPipeline pipeline, HostRedactionRequest request)
        => pipeline.RedactAndScanAsync(request, sessionId: null, TestContext.Current.CancellationToken);

    private static JsonElement Json(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public async Task TextContent_WithEmail_ReturnsPlaceholder_AndNoFinding()
    {
        var (pipeline, _) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromText($"mail {Email}")] });

        Assert.Equal("mail [EMAIL_1]", Placeholders.Untag(result.Content[0].Text));
        Assert.Empty(result.Findings);
        Assert.Null(result.Error);
        Assert.Equal(1, result.RedactedByType["EMAIL"]);
        Assert.True(result.Redacted);
        Assert.False(result.FellBack);
    }

    [Fact]
    public async Task JsonContent_KeepsShape_RedactsStringValuesOnly()
    {
        var (pipeline, _) = Build();
        var input = Json($$"""{"user":"{{Email}}","n":3,"ok":true,"{{Email}}":null}""");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromJson(input)] });

        Assert.Null(result.Content[0].Text);
        var output = Assert.NotNull(result.Content[0].Json);
        var names = new List<string>();
        foreach (var property in output.EnumerateObject())
        {
            names.Add(property.Name);
        }
        Assert.Equal(["user", "n", "ok", Email], names);
        Assert.Equal(3, output.GetProperty("n").GetInt32());
        Assert.True(output.GetProperty("ok").GetBoolean());
        Assert.Equal(JsonValueKind.Null, output.GetProperty(Email).ValueKind);
        Assert.Matches(@"^\[EMAIL_1_[a-z][a-z0-9]{5}\]$", output.GetProperty("user").GetString());
    }

    [Fact]
    public async Task RedactedContent_WritesOneRedactedEntry_CountsOnly()
    {
        var (pipeline, audit) = Build();

        await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromText($"mail {Email}")] });

        var entries = await RecordingAuditForwarder.ReadAllAsync(audit);
        var redacted = Assert.Single(entries, e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
        Assert.Equal("REDACTED", redacted.PolicyCode);
        Assert.Equal(Severity.None, redacted.Severity);
        Assert.Equal("Redacted 1 EMAIL", redacted.Summary);
        foreach (var e in entries)
        {
            Assert.DoesNotContain(Email, e.Summary, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ValueInContextAndContent_CountedOnceForContent()
    {
        var (pipeline, audit) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Context = [new(ChatRole.User, $"tool:x input:{{\"to\":\"{Email}\"}}")],
            Content = [HostContent.FromText($"sent to {Email}")],
        });

        var redacted = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit),
            e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
        Assert.Equal("Redacted 1 EMAIL", redacted.Summary);
        Assert.Equal(1, result.RedactedByType["EMAIL"]);
        foreach (var finding in result.Findings)
        {
            Assert.NotEqual("SEC-23", finding.Detection.DetectorId.Value, StringComparer.Ordinal);
        }
    }

    [Fact]
    public async Task SecretInContent_MintedAsNotToolRestorable()
    {
        var (pipeline, _) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Content = [HostContent.FromText($"{ApiKey} owner {Email}")],
        });

        var secret = Assert.Single(result.Minted, m => m.Token.StartsWith("[API_KEY_", StringComparison.Ordinal));
        Assert.False(secret.RestoreIntoToolArguments);
        var email = Assert.Single(result.Minted, m => m.Token.StartsWith("[EMAIL_", StringComparison.Ordinal));
        Assert.True(email.RestoreIntoToolArguments);
        Assert.Equal(Email, email.Value);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task RedactorThrows_FallsBack_SeverityActionAndNotRedacted()
    {
        var (pipeline, audit) = Build(o =>
        {
            o.AddDetector(_ => new ThrowingRedactor());
            o.Configure<ThrowingRedactor>(c => c.Action = SentinelAction.Redact);
        });
        var input = HostContent.FromText($"mail {Email}");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [input] });

        Assert.True(result.FellBack);
        Assert.Equal(input.Text, Assert.Single(result.Content).Text);
        Assert.False(result.Redacted);
        Assert.Empty(result.Minted);
        Assert.IsType<SentinelError.ThreatDetected>(result.Error);
        var entries = await RecordingAuditForwarder.ReadAllAsync(audit);
        Assert.Contains(entries, e => e.Summary.EndsWith("; not redacted", StringComparison.Ordinal));
        foreach (var e in entries)
        {
            Assert.DoesNotContain(Email, e.Summary, StringComparison.Ordinal);
            Assert.NotEqual(AuditEntryRedactionExtensions.RedactedPolicyCode, e.PolicyCode, StringComparer.Ordinal);
        }
    }

    [Fact]
    public async Task KnownPlaceholders_AreExempt()
    {
        var (pipeline, _) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Content = [HostContent.FromText("api_key=[API_KEY_1_k3f9x2]")],
            KnownPlaceholders = new HashSet<string>(StringComparer.Ordinal) { "[API_KEY_1_k3f9x2]" },
        });

        Assert.Empty(result.Findings);
        Assert.Null(result.Error);
    }

    // A placeholder from an earlier call is no value: it is left as it is, so it stays restorable from the store.
    [Fact]
    public async Task KnownPlaceholders_AreNotRedactedAgain()
    {
        var (pipeline, _) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Content = [HostContent.FromText("api_key=[API_KEY_1_k3f9x2]")],
            KnownPlaceholders = new HashSet<string>(StringComparer.Ordinal) { "[API_KEY_1_k3f9x2]" },
        });

        Assert.Equal("api_key=[API_KEY_1_k3f9x2]", result.Content[0].Text);
        Assert.False(result.Redacted);
        Assert.Empty(result.Minted);
    }

    [Fact]
    public async Task NoRedactors_ScansUnchanged()
    {
        var (pipeline, audit) = Build(o => o.RedactByDefault = false);
        var input = HostContent.FromText($"mail {Email}");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [input] });

        Assert.Equal(input.Text, Assert.Single(result.Content).Text);
        Assert.False(result.Redacted);
        Assert.False(result.FellBack);
        Assert.Contains(result.Findings, f => string.Equals(f.Detection.DetectorId.Value, "SEC-23", StringComparison.Ordinal));
        foreach (var e in await RecordingAuditForwarder.ReadAllAsync(audit))
        {
            Assert.NotEqual(AuditEntryRedactionExtensions.RedactedPolicyCode, e.PolicyCode, StringComparer.Ordinal);
        }
    }

    [Fact]
    public async Task Unredactable_IsScannedVerbatim()
    {
        var (pipeline, _) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Content = [HostContent.FromText("nothing here")],
            Unredactable = [new(ChatRole.Assistant, $"oversize block with {Email}")],
        });

        Assert.False(result.Redacted);
        Assert.Contains(result.Findings, f => string.Equals(f.Detection.DetectorId.Value, "SEC-23", StringComparison.Ordinal));
        Assert.IsType<SentinelError.ThreatDetected>(result.Error);
    }

    [Fact]
    public void HostContent_ToString_NeverPrintsValue()
    {
        Assert.DoesNotContain(Email, HostContent.FromText(Email).ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Email, HostContent.FromJson(Json($"\"{Email}\"")).ToString(), StringComparison.Ordinal);
    }
}
