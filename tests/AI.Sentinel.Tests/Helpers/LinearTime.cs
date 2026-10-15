using System.Diagnostics;
using Xunit;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>
/// Asserts that an operation scales linearly with its input, without depending on how fast the machine is
/// or how loaded it is at that moment. A fixed wall-clock bound fails on a busy build agent, typically right
/// after a build, while a ratio between two input sizes measured back to back is stable.
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

        // Warm up: JIT, regex construction and caches would otherwise land in the first measurement.
        run(small);
        run(large);

        var tSmall = Best(small, run);
        var tLarge = Best(large, run);
        var limit = (tSmall * 8) + TimeSpan.FromMilliseconds(50);
        Xunit.Assert.True(tLarge <= limit, $"n: {tSmall.TotalMilliseconds:F1} ms, 4n: {tLarge.TotalMilliseconds:F1} ms, limit {limit.TotalMilliseconds:F1} ms");
    }

    // The fastest of three runs: interference from other work only ever adds time.
    private static TimeSpan Best(string input, Action<string> run)
    {
        var best = TimeSpan.MaxValue;
        for (var i = 0; i < 3; i++)
        {
            var sw = Stopwatch.StartNew();
            run(input);
            sw.Stop();
            if (sw.Elapsed < best)
            {
                best = sw.Elapsed;
            }
        }
        return best;
    }
}
