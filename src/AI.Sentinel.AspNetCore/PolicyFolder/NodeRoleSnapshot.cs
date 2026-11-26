using System.Security.Claims;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The roles of one published node configuration. A request that compares the organisation and checks a role per item
/// takes one snapshot, so every answer comes from the same version even when the policy folder changes during the request.</summary>
internal sealed class NodeRoleSnapshot(NodeConfiguration configuration, NodeRoles roles)
{
    /// <summary>The organisation the configuration names.</summary>
    public string Organisation => configuration.Organisation;

    /// <summary>The id of the organisation node.</summary>
    public string OrganisationNodeId => NodeRoles.OrganisationOf(configuration);

    /// <summary>Whether <paramref name="nodeId"/> has detailed logging in this configuration; false for a node it does not hold.</summary>
    public bool DetailedLogging(string? nodeId) =>
        configuration.Nodes.FirstOrDefault(n => string.Equals(n.Id, nodeId, StringComparison.Ordinal))?.DetailedLogging == true;

    /// <summary>Whether <paramref name="user"/> holds at least <paramref name="needed"/> on <paramref name="nodeId"/> in this
    /// configuration. A node the configuration does not hold gives the lowest role.</summary>
    public bool Allows(ClaimsPrincipal user, NodeRole needed, string nodeId) =>
        NodeRoles.RoleIn(configuration, roles.GroupsOf(user), nodeId) >= needed;
}
