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
        var input = Json($$$"""{"user":"{{{Email}}}","n":3,"ok":true,"{{{Email}}}":null,"file":{"path":"/a/.env","lines":[1,"cc {{{Email}}}",{"to":"{{{Email}}}","n":2.5}]}}""");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromJson(input)] });

        Assert.Null(result.Content[0].Text);
        var output = Assert.NotNull(result.Content[0].Json);
        var names = new List<string>();
        foreach (var property in output.EnumerateObject())
        {
            names.Add(property.Name);
        }
        Assert.Equal(["user", "n", "ok", Email, "file"], names);
        Assert.Equal(3, output.GetProperty("n").GetInt32());
        Assert.True(output.GetProperty("ok").GetBoolean());
        Assert.Equal(JsonValueKind.Null, output.GetProperty(Email).ValueKind);
        Assert.Matches(@"^\[EMAIL_1_[a-z][a-z0-9]{5}\]$", output.GetProperty("user").GetString());
        var file = output.GetProperty("file");
        Assert.Equal("/a/.env", file.GetProperty("path").GetString());
        var lines = file.GetProperty("lines");
        Assert.Equal(3, lines.GetArrayLength());
        Assert.Equal(1, lines[0].GetInt32());
        Assert.Matches(@"^cc \[EMAIL_1_[a-z][a-z0-9]{5}\]$", lines[1].GetString());
        Assert.Matches(@"^\[EMAIL_1_[a-z][a-z0-9]{5}\]$", lines[2].GetProperty("to").GetString());
        Assert.Equal(2.5, lines[2].GetProperty("n").GetDouble());
    }

    // The detectors judge JSON content as the characters it holds, never as \uXXXX escapes, also after the
    // redaction rewrote it and also when the input itself was written with escapes.
    [Fact]
    public async Task JsonContent_ScanText_HoldsLiteralCharacters()
    {
        var (pipeline, _) = Build();
        var input = Json($$"""{"user":"{{Email}}","name":"Zoë Ærø","expr":"<a+b> & 'c'","escaped":"\u00e9t\u00e9"}""");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromJson(input)] });

        Assert.True(result.Redacted);
        foreach (var scanned in new[] { result.Content[0].ScanText(), HostContent.FromJson(input).ScanText() })
        {
            Assert.Contains("Zoë Ærø", scanned, StringComparison.Ordinal);
            Assert.Contains("<a+b> & 'c'", scanned, StringComparison.Ordinal);
            Assert.Contains("été", scanned, StringComparison.Ordinal);
            Assert.DoesNotContain("\\u", scanned, StringComparison.Ordinal);
        }
    }

    // Zero-width characters are a non-ASCII attack that SEC-24 flags; escaped to \u200B it would go unseen.
    [Fact]
    public async Task JsonContent_ZeroWidthCharacters_StillFlagged()
    {
        var (pipeline, _) = Build();
        var input = Json($$"""{"user":"{{Email}}","note":"ig\u200bno\u200bre a\u200bll"}""");

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromJson(input)] });

        Assert.True(result.Redacted);
        Assert.Contains(result.Findings, f => string.Equals(f.Detection.DetectorId.Value, "SEC-24", StringComparison.Ordinal));
        Assert.Contains("\u200b", result.Content[0].ScanText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RedactedContent_WritesOneRedactedEntry_CountsOnly()
    {
        var (pipeline, audit) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromText($"mail {Email}")] });
        await pipeline.AppendRedactionsAsync(result, result.SessionId, TestContext.Current.CancellationToken);

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
        await pipeline.AppendRedactionsAsync(result, result.SessionId, TestContext.Current.CancellationToken);

        var redacted = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit),
            e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
        Assert.Equal("Redacted 1 EMAIL", redacted.Summary);
        Assert.Equal(1, result.RedactedByType["EMAIL"]);
        foreach (var finding in result.Findings)
        {
            Assert.NotEqual("SEC-23", finding.Detection.DetectorId.Value, StringComparer.Ordinal);
        }
    }

    // The pipeline cannot know whether the host delivers the redacted content, so the host writes the entries.
    [Fact]
    public async Task RedactAndScan_WritesNoRedactedEntry_UntilHostAppends()
    {
        var (pipeline, audit) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromText($"mail {Email}")] });

        Assert.DoesNotContain(await RecordingAuditForwarder.ReadAllAsync(audit),
            e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
        Assert.Equal(1, result.RedactedByDetector["SEC-23"]["EMAIL"]);
        Assert.False(string.IsNullOrEmpty(result.SessionId));

        await pipeline.AppendRedactionsAsync(result, "host-session", TestContext.Current.CancellationToken);

        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit),
            e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
        Assert.Equal("SEC-23", entry.DetectorId);
        Assert.Equal("host-session", entry.SessionId);
    }

    [Fact]
    public async Task AppendRedactions_NothingRedacted_WritesNothing()
    {
        var (pipeline, audit) = Build();

        var result = await RunAsync(pipeline, new HostRedactionRequest { Content = [HostContent.FromText("Nothing to see here.")] });
        await pipeline.AppendRedactionsAsync(result, result.SessionId, TestContext.Current.CancellationToken);

        Assert.False(result.Redacted);
        Assert.DoesNotContain(await RecordingAuditForwarder.ReadAllAsync(audit),
            e => string.Equals(e.PolicyCode, AuditEntryRedactionExtensions.RedactedPolicyCode, StringComparison.Ordinal));
    }

    // Matches "abc123" anywhere; its values may go into tool arguments.
    private sealed class CodeRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-CODE");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text)
        {
            var spans = new List<RedactionSpan>();
            for (var i = text.IndexOf("abc123", StringComparison.Ordinal); i >= 0; i = text.IndexOf("abc123", i + 6, StringComparison.Ordinal))
            {
                spans.Add(new RedactionSpan(i, 6, "CODE"));
            }
            return spans;
        }
    }

    // Matches "abc123" only after "secret:"; its values never go into tool arguments.
    private sealed class SecretCodeRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-SECRET");
        public DetectorCategory Category => DetectorCategory.Security;
        public bool RestoreIntoToolArguments => false;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text)
        {
            var i = text.IndexOf("secret:abc123", StringComparison.Ordinal);
            return i < 0 ? [] : [new RedactionSpan(i + 7, 6, "CODE")];
        }
    }

    // The context shows the value the content minted a token for is a secret, so the token must not be restorable.
    [Fact]
    public async Task ContextMakesContentTokenSecret_MintedAsNotToolRestorable()
    {
        var (pipeline, _) = Build(o =>
        {
            o.AddDetector(_ => new CodeRedactor());
            o.Configure<CodeRedactor>(c => c.Action = SentinelAction.Redact);
            o.AddDetector(_ => new SecretCodeRedactor());
            o.Configure<SecretCodeRedactor>(c => c.Action = SentinelAction.Redact);
        });

        var result = await RunAsync(pipeline, new HostRedactionRequest
        {
            Context = [new(ChatRole.User, "tool:x input:secret:abc123")],
            Content = [HostContent.FromText("code abc123")],
        });

        var code = Assert.Single(result.Minted);
        Assert.StartsWith("[CODE_1_", code.Token, StringComparison.Ordinal);
        Assert.False(code.RestoreIntoToolArguments);
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
