using System.Runtime.ExceptionServices;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The order a policy is evaluated in (#658): the resident process first, then the module in the hook process, then the server once
/// one exists. The first place that answers decides. A place that has no answer in its budget, or fails, passes the call on to the next.
/// When none answers the call fails, and the hook blocks it: a call that could not be evaluated is not allowed.
/// </summary>
/// <param name="evaluators">The places, in the order they are asked.</param>
internal sealed class EvaluationOrder(IReadOnlyList<IPolicyEvaluator> evaluators)
{
    public PolicyAnswer Evaluate(string inputJson) =>
        TryEvaluate(inputJson) ?? throw new InvalidOperationException("no place could evaluate the policy: the resident process did not answer and the hook has no module to run");

    /// <summary>The answer of the first place that has one; <see langword="null"/> when none has, and none failed, which is the case
    /// the fail mode decides (#673). A failure of a place is rethrown when none answers, as for <see cref="Evaluate"/>.</summary>
    public PolicyAnswer? TryEvaluate(string inputJson)
    {
        ArgumentNullException.ThrowIfNull(inputJson);
        ExceptionDispatchInfo? firstFailure = null;
        foreach (var evaluator in evaluators)
        {
            try
            {
                if (evaluator.Evaluate(inputJson) is { } decision)
                {
                    return new PolicyAnswer(decision, evaluator.Place);
                }
            }
#pragma warning disable CA1031 // A failing place passes the call on; the first failure is rethrown when none answers.
            catch (Exception e)
#pragma warning restore CA1031
            {
                firstFailure ??= ExceptionDispatchInfo.Capture(e);
            }
        }

        firstFailure?.Throw();
        return null;
    }
}
