using System.Globalization;

namespace AI.Sentinel.ComplianceEval;

/// <summary>The review-candidacy columns of a summary row, read from fit phrases only: the lowest, over fit positives,
/// of the highest similarity to any of the detector's sets, which is the highest <c>ReviewThreshold</c> at which every
/// fit positive is a review candidate, and the count of fit legitimate texts that reach it.</summary>
internal sealed class ReviewCandidacy
{
    private readonly List<float> _legitimate = [];

    /// <summary>The lowest fit-positive any-set similarity; <see cref="float.MaxValue"/> before one is recorded.</summary>
    public float LowestPositive { get; private set; } = float.MaxValue;

    /// <summary>Records a fit phrase with its highest similarity to any of the detector's sets.</summary>
    public void Record(bool positive, float anySetSimilarity)
    {
        if (positive) LowestPositive = Math.Min(LowestPositive, anySetSimilarity);
        else _legitimate.Add(anySetSimilarity);
    }

    /// <summary>The lowest fit positive, or <c>n/a</c> without one.</summary>
    public string LowestPositiveCell() => Evaluator.Format(LowestPositive);

    /// <summary>Fit legitimate texts whose any-set similarity reaches <see cref="LowestPositive"/>.</summary>
    public string LegitimateAtOrAboveCell() => LowestPositive == float.MaxValue
        ? "n/a"
        : _legitimate.Count(a => a >= LowestPositive).ToString(CultureInfo.InvariantCulture);
}
