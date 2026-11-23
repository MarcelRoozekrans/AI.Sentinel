using System.Text.Json;
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
    private readonly Dictionary<string, string> _owners;

    private NodeConfiguration(
        string organisation, long? version, Dictionary<string, ConfiguredNode> nodes, Dictionary<string, string> owners, IReadOnlyList<RoleBinding> roles)
    {
        Organisation = organisation;
        Version = version;
        _nodes = nodes;
        _owners = owners;
        Roles = roles;
    }

    public string Organisation { get; }

    /// <summary>The version the filler stated, or <see langword="null"/>.</summary>
    public long? Version { get; }

    public IReadOnlyCollection<ConfiguredNode> Nodes => _nodes.Values;

    public IReadOnlyList<RoleBinding> Roles { get; }

    /// <summary>The node that owns <paramref name="repository"/>, or <see langword="null"/> when none does.</summary>
    public ConfiguredNode? NodeFor(string repository) =>
        _owners.TryGetValue(Normalize(repository), out var id) ? _nodes[id] : null;

    /// <summary>The map the hooks cache as <c>nodes.json</c> in the resident state folder: repository to node id, as a JSON object.</summary>
    public byte[] ToNodeMapJson() => JsonSerializer.SerializeToUtf8Bytes(_owners, NodeConfigurationJsonContext.Default.DictionaryStringString);

    /// <summary>Lower case, no scheme, no credentials, no <c>.git</c> and no trailing slash, so a url and a name for one repository meet.</summary>
    public static string Normalize(string repository)
    {
        var text = repository.Trim().ToLowerInvariant();
        var scheme = text.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            text = text[(scheme + 3)..];
        }

        var at = text.IndexOf('@', StringComparison.Ordinal);
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        if (at >= 0 && (slash < 0 || at < slash))
        {
            text = text[(at + 1)..];
        }

        // scp style: host:owner/name
        var colon = text.IndexOf(':', StringComparison.Ordinal);
        slash = text.IndexOf('/', StringComparison.Ordinal);
        if (colon >= 0 && (slash < 0 || colon < slash))
        {
            text = text[..colon] + "/" + text[(colon + 1)..];
        }

        text = text.TrimEnd('/');
        return text.EndsWith(".git", StringComparison.Ordinal) ? text[..^4] : text;
    }

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
            if (string.IsNullOrWhiteSpace(repository) || node is null || !nodes.ContainsKey(node))
            {
                throw new InvalidDataException($"a repository is assigned to the unknown node '{node}'");
            }

            if (!owners.TryAdd(Normalize(repository), node))
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

        var lifetime = settings?.ProfileLifetimeHours is { } hours ? TimeSpan.FromHours(hours) : parent?.ProfileLifetime;
        return new ConfiguredNode(
            node.Id, parent is null, failMode, lifetime, settings?.DetailedLogging ?? parent?.DetailedLogging ?? false,
            settings?.SeverityDefaults ?? parent?.SeverityDefaults ?? new Dictionary<string, string>(StringComparer.Ordinal));
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
