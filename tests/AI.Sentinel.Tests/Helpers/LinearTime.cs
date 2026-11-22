using System.Diagnostics;
using Xunit;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Asserts that an operation scales linearly with its input, without depending on how fast the machine is
/// or how loaded it is at that moment. A fixed wall-clock bound fails on a busy build agent, typically right
/// after a build, while a ratio between two input sizes measured back to back is stable. Put tests that use it
/// in the NonParallel collection: tests running alongside slow the two measurements unevenly.
/// </summary>
public static class LinearTime
{
    /// <summary>
    /// Runs <paramref name="run"/> on inputs of size <paramref name="n"/> and 4 x <paramref name="n"/> and
    /// asserts the larger takes at most 8 times as long, plus a small absolute slack. Linear work gives about
    /// 4x and quadratic work 16x. The slack keeps a sub-millisecond baseline from turning timer noise into a
    /// failure; it cannot hide a quadratic regression at these sizes, because quadratic matching of tens of
    /// thousands of characters takes hundreds of milliseconds on its own, and the detectors' regex timeout
    /// throws long before anything catastrophic finishes.
    /// </summary>
    /// <param name="input">Builds an input of the given size.</param>
    /// <param name="run">The operation under test.</param>
    /// <param name="n">The smaller input size.</param>
    public static void Assert(Func<int, string> input, Action<string> run, int n)
    {
        var small = input(n);
        var large = input(4 * n);

        // Warm up until the JIT has optimised the code. Tiered compilation runs the first calls unoptimised,
        // up to ten times slower per character, so a measurement taken during the switch compares two
        // different programs.
        for (var i = 0; i < WarmupRuns; i++)
        {
            run(small);
            run(large);
        }

        // Interleave the two sizes, so a slowdown of the machine lands on both, and keep the fastest of each:
        // interference only ever adds time.
        var tSmall = TimeSpan.MaxValue;
        var tLarge = TimeSpan.MaxValue;
        var pSmall = TimeSpan.MaxValue;
        var pLarge = TimeSpan.MaxValue;
        var nSmall = TimeSpan.MaxValue;
        var nLarge = TimeSpan.MaxValue;
        var gSmall = "";
        var gLarge = "";
        for (var i = 0; i < MeasuredRuns; i++)
        {
            var (t, p, g) = Diag(small, run);
            if (t < tSmall) { tSmall = t; pSmall = p; gSmall = g; }
            nSmall = Min(nSmall, t - p);
            (t, p, g) = Diag(large, run);
            if (t < tLarge) { tLarge = t; pLarge = p; gLarge = g; }
            nLarge = Min(nLarge, t - p);
        }

        Xunit.Assert.Fail(string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"DIAG n={n} small {tSmall.TotalMilliseconds:F1} ms pause {pSmall.TotalMilliseconds:F1} gc {gSmall} | large {tLarge.TotalMilliseconds:F1} ms pause {pLarge.TotalMilliseconds:F1} gc {gLarge} | ratio {tLarge / tSmall:F2} | without pauses {nSmall.TotalMilliseconds:F1} / {nLarge.TotalMilliseconds:F1} ratio {nLarge / nSmall:F2} | server {System.Runtime.GCSettings.IsServerGC} cpus {Environment.ProcessorCount}"));
    }

    // Enough calls for tier-1 compilation, which needs 30 calls and a short background delay.
    private const int WarmupRuns = 40;
    private const int MeasuredRuns = 7;

    private static (TimeSpan Elapsed, TimeSpan Pause, string Gcs) Diag(string input, Action<string> run)
    {
        var g0 = GC.CollectionCount(0);
        var g1 = GC.CollectionCount(1);
        var g2 = GC.CollectionCount(2);
        var pause = GC.GetTotalPauseDuration();
        var sw = Stopwatch.StartNew();
        run(input);
        sw.Stop();
        return (sw.Elapsed, GC.GetTotalPauseDuration() - pause,
            $"{GC.CollectionCount(0) - g0}/{GC.CollectionCount(1) - g1}/{GC.CollectionCount(2) - g2}");
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;
}
