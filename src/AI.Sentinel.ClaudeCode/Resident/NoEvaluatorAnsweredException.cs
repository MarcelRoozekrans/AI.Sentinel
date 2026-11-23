namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>No place had an answer for a call and none failed: the resident process stayed silent within its budget and the hook has
/// no module to run. That is the case the fail mode decides (#673); a place that fails is a policy that errored, and that is not.</summary>
internal sealed class NoEvaluatorAnsweredException()
    : InvalidOperationException("no place could evaluate the policy: the resident process did not answer and the hook has no module to run");
