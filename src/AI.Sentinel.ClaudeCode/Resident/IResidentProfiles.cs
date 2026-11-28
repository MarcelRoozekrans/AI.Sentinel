using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The warm profile modules of the resident process, as one hook call asks them (#729). The seam a test replaces.</summary>
internal interface IResidentProfiles
{
    /// <summary>The decision of the warm module of the profile of <paramref name="repository"/>, when it is the module of
    /// <paramref name="moduleHash"/>; <see langword="null"/> when the process gives no answer within the budget of the call.</summary>
    /// <exception cref="PolicyBundleException">The module failed while it ran in the process; no other place may answer instead.</exception>
    RegoDecision? Evaluate(string repository, string moduleHash, string inputJson);
}
