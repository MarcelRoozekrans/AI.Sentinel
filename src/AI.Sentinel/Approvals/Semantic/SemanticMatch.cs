using System.Globalization;

namespace AI.Sentinel.Approvals.Semantic;

/// <summary>The outcome of scoring one covered tool call against the semantic approval examples.</summary>
/// <param name="Key">The <c>semantic.tools</c> key, as written, that covers the tool.</param>
/// <param name="Spec">The spec registered under <paramref name="Key"/>.</param>
internal abstract record SemanticMatch(string Key, SemanticApprovalSpec Spec)
{
    private const string TruncatedSuffix = " (text truncated)";

    /// <summary>What the approver is shown, or <see langword="null"/> when no approval is needed.</summary>
    public abstract string? Reason { get; }

    /// <summary>No text reached the threshold: the call needs no semantic approval.</summary>
    internal sealed record NotFlagged(string Key, SemanticApprovalSpec Spec) : SemanticMatch(Key, Spec)
    {
        public override string? Reason => null;
    }

    /// <summary>A text reached the threshold: the call needs approval.</summary>
    /// <param name="Score">The highest similarity over the scored texts and the examples.</param>
    /// <param name="Threshold">The threshold in force for the call.</param>
    /// <param name="Path">The path of the text that scored highest, <c>$</c> for the whole arguments JSON.</param>
    /// <param name="Example">The example closest to that text.</param>
    /// <param name="Truncated">Whether any scored text was cut to the size cap.</param>
    internal sealed record Flagged(
        string Key, SemanticApprovalSpec Spec, float Score, float Threshold, string Path, string Example, bool Truncated)
        : SemanticMatch(Key, Spec)
    {
        // Invariant culture: the copy must not turn 0.87 into 0,87 on a host with a decimal comma.
        public override string Reason =>
            string.Create(CultureInfo.InvariantCulture, $"Semantic match {Score:0.00} ≥ {Threshold:0.00} on {Path}: \"{Example}\"")
            + (Truncated ? TruncatedSuffix : string.Empty);
    }

    /// <summary>The texts could not be scored: the call needs approval (fail closed).</summary>
    /// <param name="Kind">The exception type name, or <c>dimension mismatch</c> or <c>empty vector</c>.</param>
    /// <param name="Truncated">Whether any selected text was cut to the size cap.</param>
    internal sealed record Failed(string Key, SemanticApprovalSpec Spec, string Kind, bool Truncated) : SemanticMatch(Key, Spec)
    {
        public override string Reason =>
            $"Semantic check failed: {Kind}; approval required (fail closed)" + (Truncated ? TruncatedSuffix : string.Empty);
    }
}
