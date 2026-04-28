using System.Text;
using BenchmarkDotNet.Attributes;
using AI.Sentinel.Mcp;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Microbenchmarks for <see cref="MessageBuilder.TruncateIfNeeded"/> — the UTF-8
/// byte-counting truncation path that runs on every tool/prompt/resource scan.
/// ASCII payloads should be near no-op; multi-byte (emoji/CJK) payloads exercise
/// the surrogate-aware walk-back after the initial char-limit overshoot.
/// </summary>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Truncate")]
public class TruncateBenchmarks
{
    private const int MaxBytes = 4096;

    private string _asciiUnder = null!;
    private string _asciiOver  = null!;
    private string _emojiUnder = null!;
    private string _emojiOver  = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Build payloads of known sizes
        _asciiUnder = new string('a', 4000);                 // 4000 bytes — under cap
        _asciiOver  = new string('a', 8000);                 // 8000 bytes — over cap, fast walk-back
        // '🦄' (U+1F984) is a surrogate pair — 2 UTF-16 code units, 4 UTF-8 bytes.
        _emojiUnder = BuildRepeated("🦄",  800);             // 800 emoji × 4 bytes = 3200 (under)
        _emojiOver  = BuildRepeated("🦄", 2400);             // 2400 emoji × 4 bytes = 9600 (over)
    }

    private static string BuildRepeated(string token, int count)
    {
        var sb = new StringBuilder(token.Length * count);
        for (var i = 0; i < count; i++) sb.Append(token);
        return sb.ToString();
    }

    [Benchmark(Baseline = true, Description = "ASCII / under cap (no-op)")]
    public string Ascii_UnderCap_NoOp() =>
        MessageBuilder.TruncateIfNeeded(_asciiUnder, MaxBytes);

    [Benchmark(Description = "ASCII / over cap (trivial walk-back)")]
    public string Ascii_OverCap_TrivialWalkBack() =>
        MessageBuilder.TruncateIfNeeded(_asciiOver, MaxBytes);

    [Benchmark(Description = "Emoji / under cap (no-op)")]
    public string Emoji_UnderCap_NoOp() =>
        MessageBuilder.TruncateIfNeeded(_emojiUnder, MaxBytes);

    [Benchmark(Description = "Emoji / over cap (surrogate-aware walk-back)")]
    public string Emoji_OverCap_SurrogateAwareWalkBack() =>
        MessageBuilder.TruncateIfNeeded(_emojiOver, MaxBytes);
}
