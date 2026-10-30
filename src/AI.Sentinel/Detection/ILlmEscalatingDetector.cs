namespace AI.Sentinel.Detection;

/// <summary>
/// Detectors that implement this interface have their findings reviewed by the pipeline's
/// <see cref="IDetectionReviewer"/> when the result is Medium or higher.
/// </summary>
public interface ILlmEscalatingDetector : IDetector
{
    /// <summary>What this detector looks for, in one or two plain sentences, for the reviewer. State the intent
    /// that counts as a hit and name the closest legitimate look-alike that does not. Do not use braces: the text
    /// is placed in a prompt.</summary>
    string ReviewCriterion { get; }
}
