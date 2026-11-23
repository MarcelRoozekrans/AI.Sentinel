using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// Which node owns which repository, as the server's node configuration says and a PC has cached it. A hook asks it with no network.
/// The cache file is read and written through <see cref="Resident.ResidentState"/>; a test builds one from entries directly.
/// </summary>
internal sealed class NodeMap
{
    /// <summary>A map that no node owns anything in.</summary>
    public static readonly NodeMap Empty = new([]);

    private readonly Dictionary<string, string> _owners;

    /// <summary>The map of <paramref name="owners"/>, repository url or name to node. A key is normalised as a remote url is, so the
    /// map can be written in either form.</summary>
    public NodeMap(IEnumerable<KeyValuePair<string, string>> owners)
    {
        ArgumentNullException.ThrowIfNull(owners);
        _owners = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (repository, node) in owners)
        {
            if (!string.IsNullOrWhiteSpace(node))
            {
                _owners[RepositoryUrl.Normalize(repository) ?? repository.Trim().ToLowerInvariant()] = node;
            }
        }
    }

    /// <summary>The node that owns <paramref name="repository"/>, or <see langword="null"/> when none does.</summary>
    public string? NodeFor(string repository) => _owners.TryGetValue(repository, out var node) ? node : null;

    /// <summary>The map as JSON, the form of the cache file.</summary>
    public byte[] ToJson() => JsonSerializer.SerializeToUtf8Bytes(_owners, NodeMapJsonContext.Default.DictionaryStringString);

    /// <summary>Reads the cache file form; throws <see cref="JsonException"/> when the bytes are not a map.</summary>
    public static NodeMap FromJson(ReadOnlySpan<byte> json) =>
        new(JsonSerializer.Deserialize(json, NodeMapJsonContext.Default.DictionaryStringString) ?? throw new JsonException("no map"));
}
