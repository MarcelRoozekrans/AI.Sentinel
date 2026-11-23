using AI.Sentinel.AspNetCore.PolicyFolder;

namespace AI.Sentinel.AspNetCore.Events;

/// <summary>What the read endpoints may show (ADR-239): activity per team, a team only with enough people, and a code per developer
/// only where the node shows names and the record was stored while it did.</summary>
internal sealed class TeamVisibility
{
    private readonly NodeConfiguration? _configuration;
    private readonly HashSet<string> _small = new(StringComparer.Ordinal);

    public TeamVisibility(NodeConfiguration? configuration, IEnumerable<ServerEvent> events, int minimumPeople)
    {
        _configuration = configuration;
        var people = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var e in events)
        {
            if (e.Node is null)
            {
                continue;
            }

            if (!people.TryGetValue(e.Node, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                people[e.Node] = set;
            }

            set.Add(e.Developer);
        }

        foreach (var (node, set) in people)
        {
            if (set.Count < minimumPeople && NodeOf(configuration, node) is { IsOrganisation: false })
            {
                _small.Add(node);
            }
        }
    }

    public static ConfiguredNode? NodeOf(NodeConfiguration? configuration, string? node) =>
        configuration is null
            ? null
            : configuration.Nodes.FirstOrDefault(n => string.Equals(n.Id, node, StringComparison.Ordinal))
              ?? configuration.Nodes.FirstOrDefault(n => n.IsOrganisation);

    /// <summary>The node a record is shown under: its own, or the organisation when the team is too small to show.</summary>
    public string? NodeFor(string? node) =>
        node is not null && _small.Contains(node) ? _configuration?.Nodes.First(n => n.IsOrganisation).Id : node;

    /// <summary>Whether the code of the developer of a record is shown: the node shows names now and the record was stored with them.</summary>
    public bool ShowsName(ServerEvent e) =>
        string.Equals(e.Visibility, ServerEvent.WithNames, StringComparison.Ordinal) && NodeOf(_configuration, e.Node)?.ShowNames == true;
}
