namespace AI.Sentinel.Profiles;

/// <summary>
/// The server public keys the plugin pinned at sign-in. Immutable: <see cref="With"/> returns a new set, for a key
/// that <see cref="ProfileVerifier"/> accepted because a pinned key endorsed it.
/// </summary>
internal sealed class PinnedProfileKeys
{
    private readonly Dictionary<string, byte[]> _keys;

    private PinnedProfileKeys(Dictionary<string, byte[]> keys) => _keys = keys;

    /// <summary>No keys: every profile is refused.</summary>
    public static PinnedProfileKeys Empty { get; } = new(new Dictionary<string, byte[]>(StringComparer.Ordinal));

    /// <summary>Pins the given 32 byte public keys.</summary>
    public static PinnedProfileKeys Create(IEnumerable<byte[]> publicKeys)
    {
        ArgumentNullException.ThrowIfNull(publicKeys);
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var key in publicKeys)
        {
            keys[ProfileKeyId.Of(CheckSize(key))] = (byte[])key.Clone();
        }
        return new PinnedProfileKeys(keys);
    }

    /// <summary>Pins public keys given as base64, the form <see cref="ToBase64"/> returns.</summary>
    /// <exception cref="FormatException">An entry is not base64 of a 32 byte key.</exception>
    public static PinnedProfileKeys FromBase64(IEnumerable<string> publicKeys)
    {
        ArgumentNullException.ThrowIfNull(publicKeys);
        var decoded = new List<byte[]>();
        foreach (var text in publicKeys)
        {
            try
            {
                decoded.Add(Convert.FromBase64String(text));
            }
            catch (ArgumentException ex)
            {
                throw new FormatException("A pinned profile key is the base64 of a 32 byte Ed25519 public key.", ex);
            }
        }
        return Create(decoded);
    }

    /// <summary>The number of pinned keys.</summary>
    public int Count => _keys.Count;

    /// <summary>A new set that also pins <paramref name="publicKey"/>.</summary>
    public PinnedProfileKeys With(byte[] publicKey)
    {
        var keys = new Dictionary<string, byte[]>(_keys, StringComparer.Ordinal)
        {
            [ProfileKeyId.Of(CheckSize(publicKey))] = (byte[])publicKey.Clone(),
        };
        return new PinnedProfileKeys(keys);
    }

    /// <summary>The pinned keys as base64, sorted by key id, for the plugin to persist.</summary>
    public IReadOnlyList<string> ToBase64() =>
        _keys.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => Convert.ToBase64String(kv.Value)).ToArray();

    internal bool TryGet(string keyId, out byte[] publicKey)
    {
        if (_keys.TryGetValue(keyId, out var found))
        {
            publicKey = found;
            return true;
        }
        publicKey = [];
        return false;
    }

    private static byte[] CheckSize(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != Ed25519Crypto.PublicKeySize)
        {
            throw new ArgumentException($"An Ed25519 public key is {Ed25519Crypto.PublicKeySize} bytes.", nameof(key));
        }
        return key;
    }
}
