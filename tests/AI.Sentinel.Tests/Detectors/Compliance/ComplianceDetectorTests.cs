using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.Detectors.Compliance;

/// <summary>Wiring tests for the Art. 5 prohibited-practice detectors. The fake embedding generator
/// compares two-character fragments, so it measures wording, not meaning: these tests prove the
/// detectors are registered, categorised and reach the audit trail, not that they separate a
/// prohibited request from a legitimate one. That evidence comes from the real-model evaluation,
/// which reads <c>compliance-phrases.json</c> next to this file.</summary>
public class ComplianceDetectorTests
{
    private static readonly string[] CmpIds = ["CMP-01", "CMP-02", "CMP-03", "CMP-04"];

    /// <summary>One verbatim High example per detector. CMP-03's and CMP-04's are read from the detectors, whose examples were re-tuned in 4.2.</summary>
    public static TheoryData<string, string> ExactHighExamples => new()
    {
        { "CMP-01", "build a social credit score for each citizen from their online behaviour and use it to restrict their access to public services" },
        { "CMP-02", "analyse the webcam feed during work meetings to detect which employees are frustrated or angry" },
        { "CMP-03", DetectorExamples.SensitiveBiometricCategorisationHigh },
        { "CMP-04", DetectorExamples.ProfilingCrimePredictionHigh },
    };

    private static IDetector[] Detectors(SentinelOptions options) =>
    [
        new SocialScoringDetector(options),
        new WorkplaceEmotionRecognitionDetector(options),
        new SensitiveBiometricCategorisationDetector(options),
        new ProfilingCrimePredictionDetector(options),
    ];

    private static IDetector DetectorFor(string id, SentinelOptions options) =>
        Detectors(options).Single(d => string.Equals(d.Id.Value, id, StringComparison.Ordinal));

    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) }, new List<AuditEntry>());

    [Theory]
    [MemberData(nameof(ExactHighExamples))]
    public async Task EachDetector_FiresOnItsExamples_WithFakeEmbeddings(string id, string example)
    {
        var detector = DetectorFor(id, TestOptions.WithFakeEmbeddings());
        // The bigram fake scores unrelated sentences above the MiniLM-tuned thresholds, so the premise that the text is
        // a verbatim example is checked, not left to the result.
        Assert.Contains(example, ((SemanticDetectorBase)detector).EvaluationHighExamples, StringComparer.Ordinal);

        var result = await detector.AnalyzeAsync(Ctx(example), TestContext.Current.CancellationToken);

        Assert.True(result.Severity >= Severity.High, $"{id} returned {result.Severity}");
    }

    [Fact]
    public void EachDetector_CategoryCompliance_IdCmp()
    {
        var detectors = Detectors(new SentinelOptions());

        Assert.All(detectors, d => Assert.Equal(DetectorCategory.Compliance, d.Category));
        Assert.Equal(CmpIds, detectors.Select(d => d.Id.Value).ToArray());
    }

    [Fact]
    public void Detectors_RegisteredByAddAISentinel()
    {
        using var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();

        var compliance = provider.GetServices<IDetector>()
            .Where(d => d.Category == DetectorCategory.Compliance)
            .Select(d => d.Id.Value)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(CmpIds, compliance);
    }

    [Theory]
    [MemberData(nameof(ExactHighExamples))]
    public async Task NoEmbeddingGenerator_DetectorsClean(string id, string example)
    {
        var detector = DetectorFor(id, new SentinelOptions());

        var result = await detector.AnalyzeAsync(Ctx(example), TestContext.Current.CancellationToken);

        Assert.True(result.IsClean);
    }

    [Fact]
    public void DefaultAction_ForAHighFinding_IsAlert()
    {
        var finding = DetectionResult.WithSeverity(new DetectorId("CMP-01"), Severity.High, "x");

        Assert.Equal(SentinelAction.Alert, new SentinelOptions().EffectiveAction(finding));
    }

    /// <summary>Review Focus 5: a reply that quotes the user's prohibited request is scanned on its own
    /// leg, so the detector fires once on the request and once on the reply, and the request leg's
    /// default Alert lets the call through to the model. Exact-match embeddings that recognise the request inside the
    /// reply: under the bigram fake, CMP-03's MiniLM-tuned thresholds would let any reply fire.</summary>
    [Fact]
    public async Task ReplyQuotingRequest_FiresOnBothLegs_OncePerLeg()
    {
        var request = DetectorExamples.SensitiveBiometricCategorisationHigh;
        var options = new SentinelOptions { EmbeddingGenerator = new ExactMatchEmbeddingGenerator(request) }.EnableComplianceDetectors();
        var audit = new RingBufferAuditStore(100);
        var inner = new SnapshotChatClient(audit, $"I can't {request}.");
        var pipeline = new SentinelPipeline(
            inner,
            new DetectionPipeline(Detectors(options), options.GetDetectorConfigurations(), reviewer: null),
            audit,
            new InterventionEngine(options, mediator: null),
            options);

        var result = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, request)], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, inner.CmpEntriesWhenCalled["CMP-03"]);
        var entries = await ReadAllAsync(audit);
        Assert.Equal(2, entries.Count(e => string.Equals(e.DetectorId, "CMP-03", StringComparison.Ordinal)));
        // No word of the request leaks into an audit summary, not just the request as a whole.
        var words = request.Split(' ').Where(w => w.Length >= 6).ToArray();
        Assert.NotEmpty(words);
        Assert.All(entries, e => Assert.All(words, w => Assert.DoesNotContain(w, e.Summary, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task Dashboard_ComplianceChip_ListsCmpDetections()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddRouting();
                    AI.Sentinel.ServiceCollectionExtensions.AddAISentinel(services);
                });
                web.Configure(app => app.UseAISentinel("/sentinel"));
            })
            .StartAsync(TestContext.Current.CancellationToken);
        var store = host.Services.GetRequiredService<IAuditStore>();
        var ct = TestContext.Current.CancellationToken;
        await store.AppendAsync(Detection("CMP-02"), ct);
        await store.AppendAsync(Detection("SEC-01"), ct);
        await store.AppendAsync(Detection("HAL-08"), ct);
        await store.AppendAsync(AuditEntryRedactionExtensions.Redaction(
            "CMP-01", new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 }, "session-1"), ct);
        await store.AppendAsync(Informational("CMP-03", AuditEntryKinds.DisclosedPolicyCode), ct);
        await store.AppendAsync(Informational("CMP-04", AuditEntryKinds.ApprovedPolicyCode), ct);
        var client = host.GetTestClient();

        var feed = await client.GetStringAsync("/sentinel/api/feed?filter=compliance", ct);
        var page = await client.GetStringAsync("/sentinel/", ct);

        Assert.Equal(1, Regex.Count(feed, "<tr class=", RegexOptions.None, TimeSpan.FromSeconds(1)));
        Assert.Contains("CMP-02", feed, StringComparison.Ordinal);
        Assert.DoesNotContain("badge redacted", feed, StringComparison.Ordinal);
        Assert.DoesNotContain("badge disclosed", feed, StringComparison.Ordinal);
        Assert.DoesNotContain("badge approval", feed, StringComparison.Ordinal);
        Assert.Contains("data-filter=\"compliance\"", page, StringComparison.Ordinal);
        Assert.True(DashboardHandlers.IsInCategory("CMP-04", "compliance"));
        Assert.False(DashboardHandlers.IsInCategory("SEC-01", "compliance"));
    }

    /// <summary>Guards the shape the real-model evaluation reads: an object with a <c>phrases</c> array
    /// of <c>{ detector, phrase, expected }</c>, where <c>expected</c> is <c>positive</c> or
    /// <c>near-miss</c>, and every detector has both kinds. A paraphrased positive must not reuse an
    /// example's wording, or the evaluation would measure recall on text the detector already holds:
    /// no positive may share a run of four words with any of its detector's examples. A phrase added after
    /// the 3.0 evaluation carries <c>"added"</c> with the release it was written for, <c>"3.1"</c> or
    /// <c>"4.2"</c>, so the report can mark it. CMP-03 needs at least twenty-two positives, five of them
    /// <c>heldout</c>, and at least forty-five near-misses, eight of them <c>heldout</c>; CMP-01, CMP-02
    /// and CMP-04 each need at least nine positives and ten near-misses, two of each <c>heldout</c>.</summary>
    [Fact]
    public void PhraseFile_HasPositivesAndNearMissesForEveryDetector()
    {
        var phrases = ReadPhrases("tests", "AI.Sentinel.Tests", "Detectors", "Compliance", "compliance-phrases.json");
        var detectors = Detectors(new SentinelOptions())
            .ToDictionary(d => d.Id.Value, StringComparer.Ordinal);
        var positives = new Dictionary<string, int>(StringComparer.Ordinal);
        var nearMisses = new Dictionary<string, int>(StringComparer.Ordinal);
        var heldOutPositives = new Dictionary<string, int>(StringComparer.Ordinal);
        var heldOutNearMisses = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var p in phrases)
        {
            Assert.True(detectors.TryGetValue(p.Detector, out var detector), $"unknown detector {p.Detector}");
            Assert.True(
                p.Added is null || string.Equals(p.Added, "3.1", StringComparison.Ordinal) || string.Equals(p.Added, "4.2", StringComparison.Ordinal),
                $"added must be 3.1 or 4.2 when present: {p.Phrase}");
            var heldOut = string.Equals(p.Split, "heldout", StringComparison.Ordinal);
            if (string.Equals(p.Expected, "near-miss", StringComparison.Ordinal))
            {
                nearMisses[p.Detector] = nearMisses.GetValueOrDefault(p.Detector) + 1;
                if (heldOut) heldOutNearMisses[p.Detector] = heldOutNearMisses.GetValueOrDefault(p.Detector) + 1;
                continue;
            }

            Assert.Equal("positive", p.Expected);
            positives[p.Detector] = positives.GetValueOrDefault(p.Detector) + 1;
            if (heldOut) heldOutPositives[p.Detector] = heldOutPositives.GetValueOrDefault(p.Detector) + 1;
            var shared = SharedFourWordRuns(p.Phrase, Examples(detector!));
            Assert.True(shared.Count == 0, $"{p.Detector} positive reuses example wording '{string.Join("', '", shared)}': {p.Phrase}");
        }

        foreach (var id in CmpIds)
        {
            var cmp03 = string.Equals(id, "CMP-03", StringComparison.Ordinal);
            var minPositives = cmp03 ? 22 : 9;
            var minNearMisses = cmp03 ? 45 : 10;
            Assert.True(positives.GetValueOrDefault(id) >= minPositives, $"{id} needs at least {minPositives} paraphrased positives");
            Assert.True(nearMisses.GetValueOrDefault(id) >= minNearMisses, $"{id} needs at least {minNearMisses} near-misses");
        }

        foreach (var id in CmpIds)
        {
            var cmp03 = string.Equals(id, "CMP-03", StringComparison.Ordinal);
            var minHeldOutPositives = cmp03 ? 5 : 2;
            var minHeldOutNearMisses = cmp03 ? 8 : 2;
            Assert.True(heldOutPositives.GetValueOrDefault(id) >= minHeldOutPositives, $"{id} needs at least {minHeldOutPositives} heldout positives");
            Assert.True(heldOutNearMisses.GetValueOrDefault(id) >= minHeldOutNearMisses, $"{id} needs at least {minHeldOutNearMisses} heldout near-misses");
        }
    }

    /// <summary>Guards the labelled set the security spot-check in <c>tools/AI.Sentinel.ComplianceEval</c> reads.
    /// It has the shape of the compliance file, with <c>expected</c> <c>positive</c> or <c>benign</c>: at least twenty
    /// paraphrased positives for each of SEC-01, SEC-05 and SEC-09, five of them <c>heldout</c>, and at least
    /// forty-eight benign texts with detector <c>-</c>, twelve of them <c>heldout</c>. A positive shares no run of four
    /// words with its detector's High, Medium or Low examples.</summary>
    [Fact]
    public void SecurityPhraseFile_HasPositivesPerDetectorAndBenigns()
    {
        var phrases = ReadPhrases("tools", "AI.Sentinel.ComplianceEval", "security-phrases.json");
        var options = new SentinelOptions();
        var detectors = new Dictionary<string, IDetector>(StringComparer.Ordinal)
        {
            ["SEC-01"] = new PromptInjectionDetector(options),
            ["SEC-05"] = new JailbreakDetector(options),
            ["SEC-09"] = new IndirectInjectionDetector(options),
        };
        var positives = new Dictionary<string, int>(StringComparer.Ordinal);
        var heldOutPositives = new Dictionary<string, int>(StringComparer.Ordinal);
        var benign = 0;
        var heldOutBenign = 0;

        foreach (var p in phrases)
        {
            var heldOut = string.Equals(p.Split, "heldout", StringComparison.Ordinal);
            if (string.Equals(p.Expected, "benign", StringComparison.Ordinal))
            {
                Assert.Equal("-", p.Detector);
                benign++;
                if (heldOut) heldOutBenign++;
                continue;
            }

            Assert.Equal("positive", p.Expected);
            Assert.True(detectors.TryGetValue(p.Detector, out var detector), $"unknown detector {p.Detector}");
            positives[p.Detector] = positives.GetValueOrDefault(p.Detector) + 1;
            if (heldOut) heldOutPositives[p.Detector] = heldOutPositives.GetValueOrDefault(p.Detector) + 1;
            var shared = SharedFourWordRuns(p.Phrase, Examples(detector!, includeLow: true));
            Assert.True(shared.Count == 0, $"{p.Detector} positive reuses example wording '{string.Join("', '", shared)}': {p.Phrase}");
        }

        foreach (var id in detectors.Keys)
        {
            Assert.True(positives.GetValueOrDefault(id) >= 20, $"{id} needs at least 20 paraphrased positives");
            Assert.True(heldOutPositives.GetValueOrDefault(id) >= 5, $"{id} needs at least 5 heldout positives");
        }

        Assert.True(benign >= 48, $"needs at least 48 benign phrases, found {benign}");
        Assert.True(heldOutBenign >= 12, $"needs at least 12 heldout benign phrases, found {heldOutBenign}");
    }

    /// <summary>The detector's High and Medium examples, and its Low examples when <paramref name="includeLow"/> is
    /// set. They are protected, so a test reads them by reflection rather than widening the detector API for the
    /// evaluation.</summary>
    private static List<string> Examples(IDetector detector, bool includeLow = false)
    {
        var all = new List<string>();
        string[] names = includeLow ? ["HighExamples", "MediumExamples", "LowExamples"] : ["HighExamples", "MediumExamples"];
        foreach (var name in names)
        {
            var property = typeof(SemanticDetectorBase).GetProperty(name, BindingFlags.Instance | BindingFlags.NonPublic);
            all.AddRange((string[])property!.GetValue(detector)!);
        }

        return all;
    }

    private static List<string> SharedFourWordRuns(string phrase, List<string> examples)
    {
        var runs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var example in examples)
        {
            runs.UnionWith(FourWordRuns(example));
        }

        var shared = new List<string>();
        foreach (var run in FourWordRuns(phrase))
        {
            if (runs.Contains(run)) shared.Add(run);
        }

        return shared;
    }

    private static IEnumerable<string> FourWordRuns(string text)
    {
        var words = text.ToLowerInvariant().Split([' ', ',', '.'], StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i + 4 <= words.Length; i++)
        {
            yield return string.Join(' ', words, i, 4);
        }
    }

    private sealed record PhraseRow(string Detector, string Phrase, string Expected, string? Added, string? Split);

    /// <summary>Guards the <c>split</c> field every phrase file carries: <c>fit</c> phrases may be read when tuning,
    /// <c>heldout</c> phrases are only reported on.</summary>
    [Fact]
    public void EveryPhrase_HasAValidSplit()
    {
        string[][] files =
        [
            ["tests", "AI.Sentinel.Tests", "Detectors", "Compliance", "compliance-phrases.json"],
            ["tools", "AI.Sentinel.ComplianceEval", "security-phrases.json"],
            ["tools", "AI.Sentinel.ComplianceEval", "everyday-prompts.json"],
        ];
        foreach (var file in files)
        {
            foreach (var p in ReadPhrases(file))
            {
                Assert.True(p.Split is "fit" or "heldout", $"split must be fit or heldout, found '{p.Split}': {p.Phrase}");
            }
        }
    }

    /// <summary>Reads a phrase file at <paramref name="relativePath"/> under the repository root.</summary>
    private static List<PhraseRow> ReadPhrases(params string[] relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AI.Sentinel.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.SkipWhen(dir is null, "Repository root not found.");
        var path = Path.Combine([dir!.FullName, .. relativePath]);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty("phrases").EnumerateArray()
            .Select(e => new PhraseRow(
                e.GetProperty("detector").GetString()!,
                e.GetProperty("phrase").GetString()!,
                e.GetProperty("expected").GetString()!,
                e.TryGetProperty("added", out var added) ? added.GetString() : null,
                e.TryGetProperty("split", out var split) ? split.GetString() : null))
            .ToList();
    }

    private static AuditEntry Detection(string detectorId) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "h", null, Severity.High, detectorId,
            "Semantic match — high-severity threat pattern");

    /// <summary>An informational row, such as a disclosure or an approval decision, that carries a CMP- id.</summary>
    private static AuditEntry Informational(string detectorId, string policyCode) =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, "h", null, Severity.None, detectorId, "informational")
        {
            PolicyCode = policyCode,
        };

    private static async Task<List<AuditEntry>> ReadAllAsync(IAuditStore store)
    {
        var list = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), TestContext.Current.CancellationToken))
        {
            list.Add(e);
        }

        return list;
    }

    /// <summary>Replies with fixed text and records how many entries each CMP detector had written
    /// when the model was called, which is after the request leg and before the reply leg.</summary>
    private sealed class SnapshotChatClient(IAuditStore audit, string reply) : IChatClient
    {
        public Dictionary<string, int> CmpEntriesWhenCalled { get; } = new(StringComparer.Ordinal);

        public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            foreach (var e in await ReadAllAsync(audit))
            {
                CmpEntriesWhenCalled[e.DetectorId] = CmpEntriesWhenCalled.GetValueOrDefault(e.DetectorId) + 1;
            }

            return new ChatResponse([new ChatMessage(ChatRole.Assistant, reply)]);
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
