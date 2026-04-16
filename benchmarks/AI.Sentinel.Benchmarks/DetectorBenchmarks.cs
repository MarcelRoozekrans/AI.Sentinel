using BenchmarkDotNet.Attributes;
using AI.Sentinel.Benchmarks.Harness;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Benchmarks;

[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Detector")]
public class DetectorBenchmarks
{
    private PromptInjectionDetector _promptInjection = null!;
    private PhantomCitationDetector _phantomCitation = null!;
    private RepetitionLoopDetector  _repetitionLoop  = null!;

    private SentinelContext _cleanCtx    = null!;
    private SentinelContext _maliciousCtx = null!;

    [GlobalSetup]
    public void Setup()
    {
        _promptInjection = new PromptInjectionDetector();
        _phantomCitation = new PhantomCitationDetector();
        _repetitionLoop  = new RepetitionLoopDetector();

        _cleanCtx     = BuildContext(MessageFactory.CleanShort);
        _maliciousCtx = BuildContext(MessageFactory.Malicious);
    }

    [Benchmark(Baseline = true, Description = "PromptInjection / clean")]
    public ValueTask<DetectionResult> PromptInjection_Clean() =>
        _promptInjection.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "PromptInjection / malicious")]
    public ValueTask<DetectionResult> PromptInjection_Malicious() =>
        _promptInjection.AnalyzeAsync(_maliciousCtx, CancellationToken.None);

    [Benchmark(Description = "PhantomCitation / clean")]
    public ValueTask<DetectionResult> PhantomCitation_Clean() =>
        _phantomCitation.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "RepetitionLoop / clean")]
    public ValueTask<DetectionResult> RepetitionLoop_Clean() =>
        _repetitionLoop.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    private static SentinelContext BuildContext(IReadOnlyList<ChatMessage> msgs) =>
        new(new AgentId("user"), new AgentId("assistant"),
            SessionId.New(), msgs, []);
}
