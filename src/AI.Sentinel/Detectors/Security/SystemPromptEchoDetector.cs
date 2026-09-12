using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

/// <summary>
/// SEC-32 — flags the system prompt appearing verbatim in the model's output.
/// </summary>
/// <remarks>
/// SEC-20 matches <em>requests</em> to reveal the system prompt. Nothing detected the prompt actually
/// leaking, although the OWASP LLM07 mapping relied on it — the gap #212 reported. This compares the
/// output against the system prompt, which <see cref="SentinelContext.SystemPrompt"/> now carries on
/// both scan legs.
/// <para>
/// Only the newest message is examined, and only when the assistant produced it. Both halves matter.
/// The request context contains the system prompt itself, so a detector reading everything would
/// match itself on every turn; and a leak sitting in conversation history would re-fire on every
/// later turn, blocking a session with no way to recover. A user pasting the prompt is likewise not
/// the model leaking it — treating it as one would let anyone force a block by quoting text they
/// already hold.
/// </para>
/// <para>
/// Matching is on normalised word runs rather than raw substrings, so a reformatted or recased leak
/// still matches. The run length is what keeps it quiet: "you are a helpful assistant" appears in a
/// large share of system prompts ever written, and flagging that would be noise rather than leakage.
/// </para>
/// </remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SystemPromptEchoDetector : IDetector, ILlmEscalatingDetector
{
    /// <summary>Consecutive words that must match. Long enough that coincidence is implausible, short
    /// enough to catch a partial leak the model paraphrased around.</summary>
    private const int ShingleWords = 8;

    /// <summary>Floor on the matched run, so eight short common words cannot trip it.</summary>
    private const int MinimumShingleCharacters = 40;

    /// <summary>Bounds the work on a very long prompt or response.</summary>
    private const int MaximumWords = 4096;

    private static readonly DetectorId _id = new("SEC-32");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        var systemPrompt = ctx.SystemPrompt;
        if (string.IsNullOrWhiteSpace(systemPrompt)) return ValueTask.FromResult(_clean);
        if (ctx.Messages.Count == 0) return ValueTask.FromResult(_clean);

        var newest = ctx.Messages[ctx.Messages.Count - 1];
        if (newest.Role != ChatRole.Assistant) return ValueTask.FromResult(_clean);

        var output = newest.Text;
        if (string.IsNullOrWhiteSpace(output)) return ValueTask.FromResult(_clean);

        var promptWords = Normalise(systemPrompt);
        if (promptWords.Count < ShingleWords) return ValueTask.FromResult(_clean);

        var outputWords = Normalise(output);
        if (outputWords.Count < ShingleWords) return ValueTask.FromResult(_clean);

        var promptShingles = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i + ShingleWords <= promptWords.Count; i++)
        {
            var shingle = Join(promptWords, i);
            if (shingle.Length >= MinimumShingleCharacters) promptShingles.Add(shingle);
        }

        if (promptShingles.Count == 0) return ValueTask.FromResult(_clean);

        for (var i = 0; i + ShingleWords <= outputWords.Count; i++)
        {
            if (promptShingles.Contains(Join(outputWords, i)))
            {
                // The matched text is the system prompt itself. Repeating it into logs, alerts and
                // audit entries would spread exactly what this detector exists to contain.
                return ValueTask.FromResult(DetectionResult.WithSeverity(
                    _id,
                    Severity.High,
                    $"Output repeats a {ShingleWords}-word run from the system prompt verbatim"));
            }
        }

        return ValueTask.FromResult(_clean);
    }

    private static string Join(List<string> words, int start)
    {
        var sb = new StringBuilder();
        for (var i = start; i < start + ShingleWords; i++)
        {
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(words[i]);
        }

        return sb.ToString();
    }

    /// <summary>Lower-cases, splits on whitespace and drops surrounding punctuation, so a leak that
    /// has been reformatted, recased or re-punctuated still matches.</summary>
    private static List<string> Normalise(string text)
    {
        var words = new List<string>();
        var current = new StringBuilder();

        foreach (var c in text)
        {
            if (char.IsLetterOrDigit(c))
            {
                current.Append(char.ToLowerInvariant(c));
                continue;
            }

            if (current.Length > 0)
            {
                words.Add(current.ToString());
                current.Clear();
                if (words.Count >= MaximumWords) return words;
            }
        }

        if (current.Length > 0 && words.Count < MaximumWords) words.Add(current.ToString());
        return words;
    }
}
