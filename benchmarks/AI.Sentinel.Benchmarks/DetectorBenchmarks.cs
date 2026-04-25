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
    // Security — SemanticDetectorBase (null EmbeddingGenerator → fast-path Clean)
    private PromptInjectionDetector   _promptInjection   = null!;
    private CredentialExposureDetector _credentialExposure = null!;
    private ToolPoisoningDetector     _toolPoisoning     = null!;
    private DataExfiltrationDetector  _dataExfiltration  = null!;
    private JailbreakDetector         _jailbreak         = null!;
    private PrivilegeEscalationDetector _privilegeEscalation = null!;

    // Hallucination — SemanticDetectorBase (null EmbeddingGenerator → fast-path Clean)
    private PhantomCitationDetector   _phantomCitation   = null!;
    private SelfConsistencyDetector   _selfConsistency   = null!;

    // Operational — rule-based
    private BlankResponseDetector     _blankResponse     = null!;
    private RepetitionLoopDetector    _repetitionLoop    = null!;
    private IncompleteCodeBlockDetector _incompleteCodeBlock = null!;
    private PlaceholderTextDetector   _placeholderText   = null!;

    // Security — SemanticDetectorBase with embedding generator (realistic performance)
    private PromptInjectionDetector          _promptInjectionSemantic     = null!;
    private JailbreakDetector                _jailbreakSemantic           = null!;
    private VectorRetrievalPoisoningDetector _vectorPoisoningSemantic     = null!;

    private SentinelContext _cleanCtx     = null!;
    private SentinelContext _maliciousCtx = null!;

    [GlobalSetup]
    public void Setup()
    {
        var opts            = new SentinelOptions();
        _promptInjection    = new PromptInjectionDetector(opts);
        _credentialExposure = new CredentialExposureDetector();
        _toolPoisoning      = new ToolPoisoningDetector(opts);
        _dataExfiltration   = new DataExfiltrationDetector(opts);
        _jailbreak          = new JailbreakDetector(opts);
        _privilegeEscalation = new PrivilegeEscalationDetector(opts);

        _phantomCitation    = new PhantomCitationDetector(opts);
        _selfConsistency    = new SelfConsistencyDetector(opts);

        _blankResponse      = new BlankResponseDetector();
        _repetitionLoop     = new RepetitionLoopDetector();
        _incompleteCodeBlock = new IncompleteCodeBlockDetector();
        _placeholderText    = new PlaceholderTextDetector();

        var semanticOpts         = SentinelOptionsFactory.WithSemanticDetection();
        _promptInjectionSemantic = new PromptInjectionDetector(semanticOpts);
        _jailbreakSemantic       = new JailbreakDetector(semanticOpts);
        _vectorPoisoningSemantic = new VectorRetrievalPoisoningDetector(semanticOpts);

        _cleanCtx     = BuildContext(MessageFactory.CleanShort);
        _maliciousCtx = BuildContext(MessageFactory.Malicious);
    }

    // --- Security ---

    [Benchmark(Baseline = true, Description = "PromptInjection / clean")]
    public ValueTask<DetectionResult> PromptInjection_Clean() =>
        _promptInjection.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "PromptInjection / malicious")]
    public ValueTask<DetectionResult> PromptInjection_Malicious() =>
        _promptInjection.AnalyzeAsync(_maliciousCtx, CancellationToken.None);

    [Benchmark(Description = "CredentialExposure / clean")]
    public ValueTask<DetectionResult> CredentialExposure_Clean() =>
        _credentialExposure.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "ToolPoisoning / clean")]
    public ValueTask<DetectionResult> ToolPoisoning_Clean() =>
        _toolPoisoning.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "DataExfiltration / clean")]
    public ValueTask<DetectionResult> DataExfiltration_Clean() =>
        _dataExfiltration.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "Jailbreak / clean")]
    public ValueTask<DetectionResult> Jailbreak_Clean() =>
        _jailbreak.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "PrivilegeEscalation / clean")]
    public ValueTask<DetectionResult> PrivilegeEscalation_Clean() =>
        _privilegeEscalation.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    // --- Hallucination ---

    [Benchmark(Description = "PhantomCitation / clean")]
    public ValueTask<DetectionResult> PhantomCitation_Clean() =>
        _phantomCitation.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "SelfConsistency / clean")]
    public ValueTask<DetectionResult> SelfConsistency_Clean() =>
        _selfConsistency.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    // --- Operational ---

    [Benchmark(Description = "BlankResponse / clean")]
    public ValueTask<DetectionResult> BlankResponse_Clean() =>
        _blankResponse.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "RepetitionLoop / clean")]
    public ValueTask<DetectionResult> RepetitionLoop_Clean() =>
        _repetitionLoop.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "IncompleteCodeBlock / clean")]
    public ValueTask<DetectionResult> IncompleteCodeBlock_Clean() =>
        _incompleteCodeBlock.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "PlaceholderText / clean")]
    public ValueTask<DetectionResult> PlaceholderText_Clean() =>
        _placeholderText.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    // --- Semantic (with EmbeddingGenerator, cache cold first run) ---

    [Benchmark(Description = "PromptInjection / semantic / clean")]
    public ValueTask<DetectionResult> PromptInjection_Semantic_Clean() =>
        _promptInjectionSemantic.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "Jailbreak / semantic / clean")]
    public ValueTask<DetectionResult> Jailbreak_Semantic_Clean() =>
        _jailbreakSemantic.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    [Benchmark(Description = "VectorRetrievalPoisoning / semantic / clean")]
    public ValueTask<DetectionResult> VectorRetrievalPoisoning_Semantic_Clean() =>
        _vectorPoisoningSemantic.AnalyzeAsync(_cleanCtx, CancellationToken.None);

    private static SentinelContext BuildContext(IReadOnlyList<ChatMessage> msgs) =>
        new(new AgentId("user"), new AgentId("assistant"),
            SessionId.New(), msgs, []);
}
