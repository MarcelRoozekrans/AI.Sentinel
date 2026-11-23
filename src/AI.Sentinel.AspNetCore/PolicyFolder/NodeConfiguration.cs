using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>
/// The node configuration of one version of the policy folder: the nodes, which repositories belong to which node, which groups
/// hold which role on which node, and per-node settings. A team inherits what it leaves unset from the organisation.
/// </summary>
internal sealed class NodeConfiguration
{
    public const string FileName = "nodes.json";
    public const string Administrator = "administrator";
    public const string TeamLead = "team_lead";

    private readonly Dictionary<string, ConfiguredNode> _nodes;

    private NodeConfiguration(
        string organisation, long? version, Dictionary<string, ConfiguredNode> nodes, Dictionary<string, string> owners, IReadOnlyList<RoleBinding> roles)
    {
        Organisation = organisation;
        Version = version;
        _nodes = nodes;
        Map = new NodeMap(owners);
        Roles = roles;
    }

    public string Organisation { get; }

    /// <summary>The version the filler stated, or <see langword="null"/>.</summary>
    public long? Version { get; }

    public IReadOnlyCollection<ConfiguredNode> Nodes => _nodes.Values;

    public IReadOnlyList<RoleBinding> Roles { get; }

    /// <summary>The repository value of the profile that holds the organisation's top-level rules, as the hooks ask for it.</summary>
    public const string OrganisationRepository = CachedNodePolicies.OrganisationRepository;

    /// <summary>The node whose bundle is the profile of <paramref name="repository"/>: the node that owns it, or the organisation
    /// node for <see cref="OrganisationRepository"/>. <see langword="null"/> when no node owns the repository.</summary>
    public ConfiguredNode? NodeFor(string repository)
    {
        if (string.Equals(repository.Trim(), OrganisationRepository, StringComparison.Ordinal))
        {
            return _nodes.Values.Single(n => n.IsOrganisation);
        }

        return Map.NodeFor(Key(repository)) is { } id ? _nodes[id] : null;
    }

    /// <summary>Which node owns which repository, as the type the hooks cache. Its <c>ToJson</c> is the node map endpoint's answer.</summary>
    public NodeMap Map { get; }

    /// <summary>The name of a repository as <see cref="NodeMap"/> and the hooks know it: the normalised remote url.</summary>
    internal static string Key(string repository) => RepositoryUrl.Normalize(repository) ?? repository.Trim().ToLowerInvariant();

    /// <summary>Reads and checks <c>nodes.json</c>.</summary>
    /// <exception cref="InvalidDataException">The text is not a valid node configuration. The message names no file content.</exception>
    public static NodeConfiguration Parse(byte[] json)
    {
        NodeConfigurationWire? wire;
        try
        {
            wire = JsonSerializer.Deserialize(json, NodeConfigurationJsonContext.Default.NodeConfigurationWire);
        }
        catch (JsonException e)
        {
            throw new InvalidDataException("nodes.json is not valid: " + e.Message.Split('.')[0], e);
        }

        if (wire is null || string.IsNullOrWhiteSpace(wire.Organisation))
        {
            throw new InvalidDataException("nodes.json names no organisation");
        }

        var nodes = ParseNodes(wire);
        var owners = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (repository, node) in wire.Repositories ?? new Dictionary<string, string>(StringComparer.Ordinal))
        {
            if (string.Equals(repository.Trim(), OrganisationRepository, StringComparison.Ordinal))
            {
                throw new InvalidDataException("the repository name * is the organisation's own and cannot be assigned to a node");
            }

            if (string.IsNullOrWhiteSpace(repository) || node is null || !nodes.ContainsKey(node))
            {
                throw new InvalidDataException($"a repository is assigned to the unknown node '{node}'");
            }

            if (!owners.TryAdd(Key(repository), node))
            {
                throw new InvalidDataException("one repository is assigned to two nodes");
            }
        }

        var roles = new List<RoleBinding>();
        foreach (var role in wire.Roles ?? [])
        {
            roles.Add(ParseRole(role, nodes));
        }

        return new NodeConfiguration(wire.Organisation.Trim(), wire.Version, nodes, owners, roles);
    }

    private static Dictionary<string, ConfiguredNode> ParseNodes(NodeConfigurationWire wire)
    {
        var nodes = new Dictionary<string, ConfiguredNode>(StringComparer.Ordinal);
        var organisation = (wire.Nodes ?? []).Where(n => string.Equals(n.Kind, "organisation", StringComparison.Ordinal)).ToList();
        if (organisation.Count != 1)
        {
            throw new InvalidDataException("nodes.json needs exactly one node of kind organisation");
        }

        var top = Build(organisation[0], null);
        nodes.Add(top.Id, top);
        foreach (var node in wire.Nodes!.Where(n => !string.Equals(n.Kind, "organisation", StringComparison.Ordinal)))
        {
            if (!string.Equals(node.Kind, "team", StringComparison.Ordinal))
            {
                throw new InvalidDataException($"a node has the unknown kind '{node.Kind}'; the kinds are organisation and team");
            }

            var team = Build(node, top);
            if (!nodes.TryAdd(team.Id, team))
            {
                throw new InvalidDataException($"the node id '{team.Id}' is used twice");
            }
        }

        return nodes;
    }

    private static ConfiguredNode Build(NodeWire node, ConfiguredNode? parent)
    {
        if (string.IsNullOrWhiteSpace(node.Id) || node.Id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            throw new InvalidDataException("a node id is empty or has a character outside letters, digits, dash, underscore and dot");
        }

        var settings = node.Settings;
        var failMode = settings?.FailMode ?? parent?.FailMode ?? ProfileFailModes.Closed;
        if (!ProfileFailModes.IsValid(failMode))
        {
            throw new InvalidDataException($"the node '{node.Id}' has the unknown fail_mode '{failMode}'");
        }

        if (settings?.ProfileLifetimeHours is <= 0)
        {
            throw new InvalidDataException($"the node '{node.Id}' has a profile lifetime of no hours");
        }

        var namesApproval = parent?.NamesApproval;
        if (settings?.Names is { } names)
        {
            if (names.Show == true && string.IsNullOrWhiteSpace(names.ApprovalReference))
            {
                throw new InvalidDataException($"the node '{node.Id}' shows names without an approval reference");
            }

            namesApproval = names.Show == true ? names.ApprovalReference!.Trim() : null;
        }

        var lifetime = settings?.ProfileLifetimeHours is { } hours ? TimeSpan.FromHours(hours) : parent?.ProfileLifetime;
        return new ConfiguredNode(
            node.Id, parent is null, failMode, lifetime, settings?.DetailedLogging ?? parent?.DetailedLogging ?? false,
            settings?.SeverityDefaults ?? parent?.SeverityDefaults ?? new Dictionary<string, string>(StringComparer.Ordinal),
            namesApproval);
    }

    private static RoleBinding ParseRole(RoleBindingWire role, Dictionary<string, ConfiguredNode> nodes)
    {
        if (string.IsNullOrWhiteSpace(role.Group) || role.Node is null || !nodes.TryGetValue(role.Node, out var node))
        {
            throw new InvalidDataException("a role binding names no group or an unknown node");
        }

        return (role.Role, node.IsOrganisation) switch
        {
            (Administrator, true) or (TeamLead, false) => new RoleBinding(role.Group, role.Role, node.Id),
            _ => throw new InvalidDataException($"the role '{role.Role}' cannot be bound on the node '{node.Id}'; an administrator is bound on the organisation and a team lead on a team"),
        };
    }
}
