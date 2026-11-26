using Microsoft.AspNetCore.Authorization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>Asks the host's authorization for at least <paramref name="Minimum"/> on a node. The resource is the node id, as a string.</summary>
internal sealed record NodeRoleRequirement(NodeRole Minimum) : IAuthorizationRequirement;
