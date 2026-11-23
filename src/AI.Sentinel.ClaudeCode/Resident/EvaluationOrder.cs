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
    public PolicyAnswer Evaluate(string inputJson)
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
        throw new NoEvaluatorAnsweredException();
    }
}
