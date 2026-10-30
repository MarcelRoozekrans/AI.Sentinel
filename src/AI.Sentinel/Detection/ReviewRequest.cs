using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>What a reviewer is asked about one detector's finding.</summary>
/// <param name="DetectorId">The detector that produced the finding.</param>
/// <param name="Criterion">What the detector looks for, in words.</param>
/// <param name="Text">The flagged text.</param>
/// <param name="Role">The role of the message the text came from, when known.</param>
/// <param name="Score">The detector's score for the text, when it has one.</param>
/// <param name="ProposedSeverity">The severity the detector proposed.</param>
/// <param name="MaximumSeverity">The highest severity the reviewer may give.</param>
public sealed record ReviewRequest(
    DetectorId DetectorId,
    string Criterion,
    string Text,
    ChatRole? Role,
    float? Score,
    Severity ProposedSeverity,
    Severity MaximumSeverity);
