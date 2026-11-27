namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The <see cref="ResidentResponse.Error"/> values of an approval operation that the server did not answer with a state.</summary>
internal static class ResidentApprovalAnswer
{
    public const string Unreachable = "unreachable";
    public const string SignInNeeded = "sign_in_needed";
    public const string Refused = "refused";
    public const string NotFound = "not_found";
}
