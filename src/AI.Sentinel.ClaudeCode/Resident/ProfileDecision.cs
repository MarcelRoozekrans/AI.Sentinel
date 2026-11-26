using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What the cached profile says about one call.</summary>
/// <param name="Decision">The decision of the profile's module; <see langword="null"/> when no valid profile is cached.</param>
/// <param name="Rejection">Why the cached profile was not used; <see cref="ProfileRejection.None"/> when it was, and
/// <see langword="null"/> when none is cached. What a hook does then is not decided here.</param>
internal sealed record ProfileDecision(RegoDecision? Decision, ProfileRejection? Rejection);
