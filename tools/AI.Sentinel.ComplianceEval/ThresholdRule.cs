namespace AI.Sentinel.ComplianceEval;

/// <summary>The tuning rule that turns the highest legitimate similarities into High and Medium thresholds.</summary>
/// <remarks>High is the highest legitimate similarity to the High set plus 0.05, Medium the highest legitimate
/// similarity to the Medium set plus 0.02, both rounded up to 0.01, with Medium kept below High. High gets the wider
/// margin because it raises an Alert; Medium is only logged.</remarks>
internal static class ThresholdRule
{
    /// <summary>The thresholds the rule gives for the highest legitimate similarities of a model.</summary>
    /// <param name="highestBenignHigh">Highest legitimate similarity to the High set.</param>
    /// <param name="highestBenignMedium">Highest legitimate similarity to the Medium set.</param>
    public static (float High, float Medium) Suggest(float highestBenignHigh, float highestBenignMedium)
    {
        var high = RoundUp(highestBenignHigh + 0.05f);
        var medium = Math.Min(RoundUp(highestBenignMedium + 0.02f), high - 0.01f);
        return (high, medium);
    }

    /// <summary>Counts how positives fare under thresholds: at High, else at Medium, else missed.</summary>
    /// <param name="positives">The High-set and Medium-set similarity of each positive.</param>
    /// <param name="high">The High threshold.</param>
    /// <param name="medium">The Medium threshold.</param>
    public static (int AtHigh, int AtMedium, int Missed) Classify(
        IEnumerable<(float High, float Medium)> positives, float high, float medium)
    {
        ArgumentNullException.ThrowIfNull(positives);
        int atHigh = 0, atMedium = 0, missed = 0;
        foreach (var (h, m) in positives)
        {
            if (h >= high) atHigh++;
            else if (m >= medium) atMedium++;
            else missed++;
        }

        return (atHigh, atMedium, missed);
    }

    private static float RoundUp(float value) => MathF.Ceiling(MathF.Round(value * 100f, 3)) / 100f;

    /// <summary>Verifies <see cref="Suggest"/>; the tool has no test project.</summary>
    internal static void SelfCheck()
    {
        Check(Suggest(0.391f, 0.246f), (0.45f, 0.27f));
        Check(Suggest(0.604f, 0.402f), (0.66f, 0.43f));
        Check(Suggest(0.50f, 0.60f), (0.55f, 0.54f));
    }

    private static void Check((float High, float Medium) actual, (float High, float Medium) expected)
    {
        if (Math.Abs(actual.High - expected.High) > 1e-4 || Math.Abs(actual.Medium - expected.Medium) > 1e-4)
        {
            throw new InvalidOperationException(
                $"ThresholdRule.Suggest self-check failed: expected {expected}, got {actual}.");
        }
    }
}
