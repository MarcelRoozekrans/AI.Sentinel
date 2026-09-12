using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

/// <summary>
/// SEC-08 — flags long, structureless, high-entropy runs: the shape encoded or encrypted data takes
/// when it is smuggled through text.
/// </summary>
/// <remarks>
/// Previously a <see cref="StubDetector"/> that always returned <c>Clean</c>. Because the escalation
/// gate in <see cref="DetectionPipeline"/> only re-classifies findings already at
/// <see cref="Severity.Medium"/> or above, it could never fire — not even with an
/// <c>EscalationClient</c> configured, which is what the stub's documentation implied. Entropy needs
/// nothing the pipeline lacks, so it is computed directly.
/// <para>
/// Precision governs the thresholds. Hashes, identifiers and URLs are long and random-looking too,
/// and a detector that flags a git SHA is one an operator switches off. A candidate must be long
/// enough to carry a payload, drawn only from an encoding alphabet — which excludes URLs and
/// anything with punctuation or structure — and carry more entropy per character than hexadecimal
/// can express, which excludes digests and commit ids.
/// </para>
/// <para>
/// The result is deliberately <see cref="Severity.Medium"/> and
/// <see cref="ILlmEscalatingDetector"/>: a high-entropy blob is suspicious, not conclusive, and that
/// is precisely what a second-pass classifier is for.
/// </para>
/// </remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class EntropyCovertChannelDetector : IDetector, ILlmEscalatingDetector
{
    /// <summary>Shorter runs cannot carry a useful payload, and short random-looking tokens are
    /// ordinary — session ids, short hashes, abbreviations.</summary>
    private const int MinimumRunLength = 40;

    /// <summary>Hexadecimal tops out at 4 bits per character and base64 at 6. Sitting above hex
    /// excludes digests, commit ids and decimal runs while still catching encoded payloads.</summary>
    private const double MinimumEntropyBitsPerChar = 4.5;

    /// <summary>Bounds the work on a very large scan.</summary>
    private const int MaximumCharactersExamined = 64 * 1024;

    private static readonly DetectorId _id = new("SEC-08");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        var text = ctx.TextContent;
        if (string.IsNullOrEmpty(text)) return ValueTask.FromResult(_clean);

        var span = text.AsSpan(0, Math.Min(text.Length, MaximumCharactersExamined));
        var start = -1;

        for (var i = 0; i <= span.Length; i++)
        {
            var inRun = i < span.Length && IsEncodingCharacter(span[i]);
            if (inRun)
            {
                if (start < 0) start = i;
                continue;
            }

            if (start >= 0)
            {
                var run = span[start..i];
                if (run.Length >= MinimumRunLength)
                {
                    var entropy = ShannonEntropy(run);
                    if (entropy >= MinimumEntropyBitsPerChar)
                    {
                        return ValueTask.FromResult(DetectionResult.WithSeverity(
                            _id,
                            Severity.Medium,
                            $"High-entropy run of {run.Length} characters ({entropy:F1} bits/char) — possible encoded payload"));
                    }
                }

                start = -1;
            }
        }

        return ValueTask.FromResult(_clean);
    }

    /// <summary>Characters an encoder emits. Excluding punctuation and separators is what keeps URLs,
    /// paths and structured identifiers out: those break into short runs.</summary>
    private static bool IsEncodingCharacter(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=' or '_';

    private static double ShannonEntropy(ReadOnlySpan<char> value)
    {
        Span<int> counts = stackalloc int[128];
        var counted = 0;

        foreach (ref readonly var c in value)
        {
            if (c < 128)
            {
                counts[c]++;
                counted++;
            }
        }

        if (counted == 0) return 0d;

        var entropy = 0d;
        foreach (ref var count in counts)
        {
            if (count == 0) continue;

            var p = (double)count / counted;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
