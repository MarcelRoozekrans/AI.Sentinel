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
/// Those rules alone flagged one file read in fifteen in a check of real tool data (#470): long test names, URL paths
/// and constants clear 4.5 bits per character, and lock files carry base64 digests. So a candidate is also passed
/// over when it is cased and voweled like words, when it is an alphabet table, when it follows a <c>sha*-</c> digest
/// prefix, and when it is an inline image or font in a <c>data:</c> URI.
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

    /// <summary>Bounds the work on a very large message: each message is examined up to this many characters.</summary>
    private const int MaximumCharactersExamined = 64 * 1024;

    /// <summary>Above this share of lower-lower, or of upper-upper, neighbours a run is cased like words. Random
    /// base64 has about 0.17 of each, so identifiers, paths and constants clear it and payloads do not.</summary>
    private const double WordCasePairShare = 0.4;

    /// <summary>Above this share of same-case neighbours of either kind a run is cased like words too, which catches
    /// identifiers that mix PascalCase and SCREAMING_CASE parts. Random base64 has about 0.33.</summary>
    private const double MixedWordCasePairShare = 0.55;

    /// <summary>Words are about two-fifths vowels; base64 and base32 letters about a fifth.</summary>
    private const double WordVowelShare = 0.28;

    /// <summary>Base32 is one case, as constants are, but about a fifth of it is the digits 2 to 7. Identifiers carry
    /// few digits.</summary>
    private const double WordDigitShare = 0.10;

    /// <summary>Above this share of neighbours that follow each other in code order, such as <c>ab</c> or <c>89</c>,
    /// a run is an alphabet table, not data.</summary>
    private const double OrderedPairShare = 0.4;

    private static readonly string[] DigestPrefixes = ["sha1-", "sha256-", "sha384-", "sha512-"];

    private static readonly string[] InlineMediaTypes = ["image/", "font/", "application/font-", "application/x-font-"];

    private static readonly DetectorId _id = new("SEC-08");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(ctx);

        // Each message on its own, newest first, so one large message, such as a file read early, cannot push later
        // ones out of the examined window.
        for (var m = ctx.Messages.Count - 1; m >= 0; m--)
        {
            var finding = Examine(SentinelContext.MessageText(ctx.Messages[m]));
            if (finding is not null) return ValueTask.FromResult(finding);
        }

        return ValueTask.FromResult(_clean);
    }

    private static DetectionResult? Examine(string text)
    {
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
                    if (entropy >= MinimumEntropyBitsPerChar && !IsLikelyBenign(span, start, run))
                    {
                        return DetectionResult.WithSeverity(
                            _id,
                            Severity.Medium,
                            $"High-entropy run of {run.Length} characters ({entropy:F1} bits/char) — possible encoded payload");
                    }
                }

                start = -1;
            }
        }

        return null;
    }

    /// <summary>
    /// Whether a high-entropy run at <paramref name="start"/> is ordinary tool data: an identifier, path or constant,
    /// which is made of words; an alphabet table; a digest after its <c>sha*-</c> prefix, as in a lock file or a
    /// subresource integrity attribute; or an inline image or font in a <c>data:</c> URI.
    /// </summary>
    private static bool IsLikelyBenign(ReadOnlySpan<char> text, int start, ReadOnlySpan<char> run) =>
        IsWordLike(run) || IsOrdered(run) || FollowsDigestPrefix(text, start) || IsInlineMedia(text, start);

    /// <summary>Cased like words, and either voweled like words or nearly free of digits, the way base32 is not.</summary>
    private static bool IsWordLike(ReadOnlySpan<char> run)
    {
        int lowerPairs = 0, upperPairs = 0;
        for (var i = 1; i < run.Length; i++)
        {
            if (char.IsAsciiLetterLower(run[i - 1]) && char.IsAsciiLetterLower(run[i])) lowerPairs++;
            else if (char.IsAsciiLetterUpper(run[i - 1]) && char.IsAsciiLetterUpper(run[i])) upperPairs++;
        }

        double pairs = run.Length - 1;
        var casedLikeWords = lowerPairs / pairs > WordCasePairShare
            || upperPairs / pairs > WordCasePairShare
            || (lowerPairs + upperPairs) / pairs > MixedWordCasePairShare;
        if (!casedLikeWords) return false;

        int letters = 0, vowels = 0, digits = 0;
        foreach (var c in run)
        {
            if (char.IsAsciiDigit(c)) digits++;
            else if (char.IsAsciiLetter(c))
            {
                letters++;
                if (char.ToLowerInvariant(c) is 'a' or 'e' or 'i' or 'o' or 'u') vowels++;
            }
        }

        return (letters > 0 && (double)vowels / letters >= WordVowelShare) || (double)digits / run.Length < WordDigitShare;
    }

    private static bool IsOrdered(ReadOnlySpan<char> run)
    {
        var ordered = 0;
        for (var i = 1; i < run.Length; i++)
        {
            if (run[i] == run[i - 1] + 1) ordered++;
        }

        return (double)ordered / (run.Length - 1) > OrderedPairShare;
    }

    private static bool FollowsDigestPrefix(ReadOnlySpan<char> text, int start)
    {
        foreach (var prefix in DigestPrefixes)
        {
            if (start >= prefix.Length && text[(start - prefix.Length)..start].Equals(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>Whether the run is the body of a <c>data:image/...;base64,</c> or font URI. Any other media type,
    /// <c>text/plain</c> for one, is a payload like any other.</summary>
    private static bool IsInlineMedia(ReadOnlySpan<char> text, int start)
    {
        const string marker = ";base64,";
        if (start < marker.Length || !text[(start - marker.Length)..start].SequenceEqual(marker)) return false;

        // A media type is short; the scheme sits just before it.
        var head = text[Math.Max(0, start - marker.Length - 128)..(start - marker.Length)];
        var scheme = head.LastIndexOf("data:", StringComparison.OrdinalIgnoreCase);
        if (scheme < 0) return false;

        var mediaType = head[(scheme + "data:".Length)..];
        foreach (var type in InlineMediaTypes)
        {
            if (mediaType.StartsWith(type, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
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
