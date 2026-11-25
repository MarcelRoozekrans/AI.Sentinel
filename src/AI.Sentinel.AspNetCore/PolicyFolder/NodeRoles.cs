using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>
/// Who may do what on which node (ADR-109, ADR-232). The roles are the group bindings of the node configuration that is current
/// when a question is asked, so a change of the policy folder changes the answers without a restart. A role applies to its node
/// and the nodes below it: an administrator is bound on the organisation and so holds the role everywhere; a team lead holds it on
/// their team. Everyone else is a developer. With no configuration published every answer is the lowest one.
/// </summary>
internal sealed class NodeRoles(PolicyFolderLoader loader, IOptions<PolicyFolderOptions> options)
{
    /// <summary>The developer a validated token stands for: its subject claim, or the claim the sign-in handler maps it to.</summary>
    public string? DeveloperOf(ClaimsPrincipal user)
    {
        var name = options.Value.DeveloperClaim;
        var value = user.FindFirst(name)?.Value;
        if (string.IsNullOrEmpty(value) && string.Equals(name, PolicyFolderOptions.DefaultDeveloperClaim, StringComparison.Ordinal))
        {
            value = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }

        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>The identity-provider groups of a validated token: every value of the groups claim, whether the provider sent one
    /// claim per group or one claim holding a JSON array.</summary>
    public IReadOnlySet<string> GroupsOf(ClaimsPrincipal user)
    {
        var groups = new HashSet<string>(StringComparer.Ordinal);
        foreach (var claim in user.FindAll(options.Value.GroupsClaim))
        {
            AddGroups(groups, claim.Value);
        }

        return groups;
    }

    /// <summary>The highest role <paramref name="user"/> holds on <paramref name="nodeId"/>.</summary>
    public NodeRole RoleOn(ClaimsPrincipal user, string nodeId) =>
        loader.Current?.Nodes is { } configuration ? RoleIn(configuration, GroupsOf(user), nodeId) : NodeRole.Developer;

    /// <summary>Whether <paramref name="user"/> holds at least <paramref name="needed"/> on <paramref name="nodeId"/>.</summary>
    public bool Allows(ClaimsPrincipal user, NodeRole needed, string nodeId) => RoleOn(user, nodeId) >= needed;

    /// <summary>Whether <paramref name="user"/> holds at least <paramref name="needed"/> on the node that owns
    /// <paramref name="repository"/>. A repository that no node owns is the organisation's to settle: only an administrator is allowed.
    /// The answer comes from one published configuration, read once.</summary>
    public bool AllowsOnSession(ClaimsPrincipal user, NodeRole needed, string repository)
    {
        if (loader.Current?.Nodes is not { } configuration)
        {
            return false;
        }

        var groups = GroupsOf(user);
        var node = configuration.NodeFor(repository)?.Id;
        return node is null
            ? RoleIn(configuration, groups, OrganisationOf(configuration)) == NodeRole.Administrator
            : RoleIn(configuration, groups, node) >= needed;
    }

    /// <summary>Whether <paramref name="user"/> is an administrator of <paramref name="organisation"/>: the current node configuration
    /// names that organisation and binds one of the user's groups as administrator. The configuration is read once, so the name and the
    /// role come from the same version.</summary>
    public bool IsAdministratorOf(ClaimsPrincipal user, string organisation)
    {
        if (loader.Current is not { } published
            || !string.Equals(published.Organisation, organisation, StringComparison.Ordinal))
        {
            return false;
        }

        return RoleIn(published.Nodes, GroupsOf(user), OrganisationOf(published.Nodes)) == NodeRole.Administrator;
    }

    private static string OrganisationOf(NodeConfiguration configuration) => configuration.Nodes.Single(n => n.IsOrganisation).Id;

    private static NodeRole RoleIn(NodeConfiguration configuration, IReadOnlySet<string> groups, string nodeId)
    {
        if (configuration.Nodes.All(n => !string.Equals(n.Id, nodeId, StringComparison.Ordinal)))
        {
            return NodeRole.Developer;
        }

        var role = NodeRole.Developer;
        foreach (var binding in configuration.Roles.Where(b => groups.Contains(b.Group)))
        {
            if (string.Equals(binding.Role, NodeConfiguration.Administrator, StringComparison.Ordinal))
            {
                return NodeRole.Administrator;
            }

            if (string.Equals(binding.Node, nodeId, StringComparison.Ordinal))
            {
                role = NodeRole.TeamLead;
            }
        }

        return role;
    }

    /// <summary>Whether <paramref name="user"/> may approve, deny, pause or release a session of <paramref name="repository"/> whose
    /// request <paramref name="requester"/> made: a team lead or administrator on its node, and never the requester themselves.</summary>
    public bool MayDecide(ClaimsPrincipal user, string repository, string requester)
    {
        var developer = DeveloperOf(user);
        return developer is not null
            && !string.Equals(developer, requester, StringComparison.Ordinal)
            && AllowsOnSession(user, NodeRole.TeamLead, repository);
    }

    /// <summary>Whether <paramref name="user"/> may read a decision about <paramref name="subject"/> on <paramref name="repository"/>:
    /// a developer their own, a team lead and an administrator those on their node.</summary>
    public bool MaySeeDecision(ClaimsPrincipal user, string repository, string subject) =>
        (DeveloperOf(user) is { } developer && string.Equals(developer, subject, StringComparison.Ordinal))
        || AllowsOnSession(user, NodeRole.TeamLead, repository);

    private static void AddGroups(HashSet<string> groups, string value)
    {
        var text = value.Trim();
        if (text.StartsWith('['))
        {
            try
            {
                using var document = JsonDocument.Parse(text);
                if (document.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in document.RootElement.EnumerateArray().Where(i => i.ValueKind == JsonValueKind.String))
                    {
                        groups.Add(item.GetString()!);
                    }

                    return;
                }
            }
            catch (JsonException)
            {
                // Not an array after all: the text is one group name.
            }
        }

        if (text.Length > 0)
        {
            groups.Add(text);
        }
    }
}
