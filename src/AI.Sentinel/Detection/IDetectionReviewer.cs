using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Decides, as a second stage after a detector, whether the content really matches what that detector
/// looks for and at which severity.</summary>
public interface IDetectionReviewer
{
    /// <summary>Reviews one detector's finding. An exception is not swallowed: the pipeline classifies the failure.</summary>
    ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken);
}
