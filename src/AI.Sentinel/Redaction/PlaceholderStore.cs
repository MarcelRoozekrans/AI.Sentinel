using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Redaction;

/// <summary>
/// The placeholders a long-lived host, such as the MCP proxy, minted across its calls, so a later tool call can get
/// the PII it names back in its arguments. Each call still redacts with its own <see cref="RedactionSession"/> and
/// tag, and registers what it minted here. Only values that may go into tool arguments are restored; a secret's
/// token is known, so a scan does not flag it, but its value is not kept, only a keyed hash of it. That hash stops
/// a value one call found as PII from being restored when another call finds it as a secret. An entry expires after it has not been
/// used for the idle expiry, and over the size cap the least recently used entry is evicted; either way its token
/// stays literal text from then on. Values are held in memory only and never printed. Safe for concurrent use.
/// </summary>
internal sealed class PlaceholderStore
{
    /// <summary>The default size cap.</summary>
    public const int DefaultMaxEntries = 10_000;

    /// <summary>The default idle expiry, 30 minutes.</summary>
    public static TimeSpan DefaultIdleExpiry { get; } = TimeSpan.FromMinutes(30);

    private readonly TimeSpan _idleExpiry;
    private readonly int _maxEntries;
    private readonly TimeProvider _time;

#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _gate = new();
#else
    private readonly object _gate = new();
#endif
    private readonly Dictionary<string, LinkedListNode<Entry>> _byToken = new(StringComparer.Ordinal);
    // Least recently used first.
    private readonly LinkedList<Entry> _byUse = new();
    // The live secret entries by the keyed hash of their value, counted, since two tokens can hold one secret.
    private readonly Dictionary<string, int> _secretHashes = new(StringComparer.Ordinal);
    // Random per store, so a hash says nothing outside this process and cannot be checked against guesses offline.
    private readonly byte[] _hashKey = RandomNumberGenerator.GetBytes(32);

    /// <summary>Creates an empty store.</summary>
    /// <param name="idleExpiry">How long an entry lives after its last registration or restore; positive.</param>
    /// <param name="maxEntries">The size cap; at least 1.</param>
    /// <param name="timeProvider">The clock; <see cref="TimeProvider.System"/> when null.</param>
    public PlaceholderStore(TimeSpan idleExpiry, int maxEntries = DefaultMaxEntries, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(idleExpiry, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _idleExpiry = idleExpiry;
        _maxEntries = maxEntries;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Never prints the mapping.</summary>
    public override string ToString() => nameof(PlaceholderStore);

    /// <summary>The number of live entries.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                PurgeExpiredLocked(_time.GetUtcNow());
                return _byToken.Count;
            }
        }
    }

    /// <summary>
    /// Adds what one call minted, as most recently used. A token registered again is refreshed. Once it is not
    /// restorable it never becomes restorable again, and a token registered with a different value is poisoned:
    /// two sessions drew the same tag, so restoring either value could hand one caller's value to another's tool
    /// call. A value registered as a secret also poisons every token that holds it as PII, in either order, for as
    /// long as the secret's entry lives: an address one call finds as an EMAIL may be another call's password. A
    /// poisoned token stays known, and literal, until it expires or is evicted.
    /// </summary>
    public void Register(IReadOnlyList<MintedPlaceholder> minted)
    {
        ArgumentNullException.ThrowIfNull(minted);
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            PurgeExpiredLocked(now);
            // This call's secrets first, so they poison its own PII tokens too, whatever the order they were minted in.
            var hashes = new string[minted.Count];
            var secrets = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < minted.Count; i++)
            {
                hashes[i] = HashOf(minted[i].Value);
                if (!minted[i].RestoreIntoToolArguments && secrets.Add(hashes[i]))
                {
                    PoisonLocked(minted[i].Value);
                }
            }

            for (var i = 0; i < minted.Count; i++)
            {
                var m = minted[i];
                var hash = hashes[i];
                // A secret's value is not kept: it is never restored, so only its token and keyed hash are needed.
                var value = m.RestoreIntoToolArguments && !secrets.Contains(hash) && !_secretHashes.ContainsKey(hash)
                    ? m.Value
                    : null;
                if (_byToken.TryGetValue(m.Token, out var node))
                {
                    // Kept only while both registrations are restorable and agree on the value; otherwise null for good.
                    var stored = node.Value.Value;
                    var kept = stored is not null && value is not null && string.Equals(stored, value, StringComparison.Ordinal)
                        ? stored
                        : null;
                    // A token two sessions minted for two secrets keeps both hashes, so both values stay secrets.
                    var secretHashes = node.Value.SecretHashes;
                    if (!m.RestoreIntoToolArguments && secretHashes?.Contains(hash, StringComparer.Ordinal) != true)
                    {
                        secretHashes = [.. secretHashes ?? [], hash];
                    }

                    RemoveLocked(node);
                    node.Value = new Entry(m.Token, kept, now, secretHashes);
                    AddLocked(node);
                    continue;
                }

                var added = new LinkedListNode<Entry>(new Entry(m.Token, value, now, m.RestoreIntoToolArguments ? null : [hash]));
                _byToken[m.Token] = added;
                AddLocked(added);
            }

            while (_byToken.Count > _maxEntries && _byUse.First is { } oldest)
            {
                RemoveLocked(oldest);
                _byToken.Remove(oldest.Value.Token);
            }
        }
    }

    /// <summary>Makes every restorable entry that holds <paramref name="secret"/> non-restorable for good.</summary>
    private void PoisonLocked(string secret)
    {
        for (var node = _byUse.First; node is not null; node = node.Next)
        {
            if (string.Equals(node.Value.Value, secret, StringComparison.Ordinal))
            {
                node.Value = node.Value with { Value = null };
            }
        }
    }

    private string HashOf(string value) =>
        Convert.ToHexString(HMACSHA256.HashData(_hashKey, Encoding.UTF8.GetBytes(value)));

    /// <summary>Appends <paramref name="node"/> as most recently used and counts its secret hashes.</summary>
    private void AddLocked(LinkedListNode<Entry> node)
    {
        _byUse.AddLast(node);
        foreach (var hash in node.Value.SecretHashes ?? [])
        {
            _secretHashes[hash] = _secretHashes.GetValueOrDefault(hash) + 1;
        }
    }

    /// <summary>Unlinks <paramref name="node"/> and stops counting its secret hashes.</summary>
    private void RemoveLocked(LinkedListNode<Entry> node)
    {
        _byUse.Remove(node);
        foreach (var hash in node.Value.SecretHashes ?? [])
        {
            if (--CollectionsMarshal.GetValueRefOrNullRef(_secretHashes, hash) == 0)
            {
                _secretHashes.Remove(hash);
            }
        }
    }

    /// <summary>Every live token, restorable or not. Tokens only, never values.</summary>
    public IReadOnlySet<string> KnownTokens()
    {
        lock (_gate)
        {
            PurgeExpiredLocked(_time.GetUtcNow());
            return new HashSet<string>(_byToken.Keys, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// <paramref name="text"/> with every live, restorable token replaced by its value, which counts as a use of
    /// that entry. Any other token, an expired or evicted one, a secret's, or one this store never saw, stays as
    /// it is.
    /// </summary>
    public string RestoreToolArgument(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return text;
        }

        lock (_gate)
        {
            var now = _time.GetUtcNow();
            PurgeExpiredLocked(now);
            if (_byToken.Count == 0)
            {
                return text;
            }

            return PlaceholderFormat.Pattern().Replace(text, m => RestoreLocked(m, now));
        }
    }

    private string RestoreLocked(Match m, DateTimeOffset now)
    {
        if (!_byToken.TryGetValue(m.Value, out var node) || node.Value.Value is not { } value)
        {
            return m.Value;
        }

        _byUse.Remove(node);
        node.Value = node.Value with { LastUsed = now };
        _byUse.AddLast(node);
        return value;
    }

    /// <summary>
    /// The tool-call arguments with every string value restored by <see cref="RestoreToolArgument"/>, at any depth.
    /// Property names, numbers, booleans, nulls and the nesting are kept. Returns <paramref name="arguments"/>
    /// itself when nothing was restored, and otherwise a new dictionary with the same comparer; the input is never
    /// mutated.
    /// </summary>
    public IDictionary<string, JsonElement>? RestoreToolArguments(IDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null || arguments.Count == 0)
        {
            return arguments;
        }

        Dictionary<string, JsonElement>? restored = null;
        foreach (var (key, value) in arguments)
        {
            var mapped = Restore(value, out var changed);
            if (changed && restored is null)
            {
                var comparer = (arguments as Dictionary<string, JsonElement>)?.Comparer ?? StringComparer.Ordinal;
                restored = new Dictionary<string, JsonElement>(arguments, comparer);
            }
            if (changed)
            {
                restored![key] = mapped;
            }
        }
        return restored ?? arguments;
    }

    private JsonElement Restore(JsonElement element, out bool changed)
    {
        changed = false;
        if (!HasRestorableString(element))
        {
            return element;
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            changed = WriteRestored(writer, element);
        }
        if (!changed)
        {
            return element;
        }

        using var doc = JsonDocument.Parse(buffer.WrittenMemory);
        return doc.RootElement.Clone();
    }

    // Cheap pre-check, so arguments with no placeholder are never rewritten.
    private static bool HasRestorableString(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString()!.Contains('[', StringComparison.Ordinal);
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (HasRestorableString(property.Value))
                    {
                        return true;
                    }
                }
                return false;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (HasRestorableString(item))
                    {
                        return true;
                    }
                }
                return false;
            default:
                return false;
        }
    }

    private bool WriteRestored(Utf8JsonWriter writer, JsonElement element)
    {
        var changed = false;
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                var original = element.GetString()!;
                var restored = RestoreToolArgument(original);
                changed = !string.Equals(original, restored, StringComparison.Ordinal);
                writer.WriteStringValue(restored);
                break;
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    changed |= WriteRestored(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    changed |= WriteRestored(writer, item);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
        return changed;
    }

    private void PurgeExpiredLocked(DateTimeOffset now)
    {
        while (_byUse.First is { } oldest && now - oldest.Value.LastUsed > _idleExpiry)
        {
            RemoveLocked(oldest);
            _byToken.Remove(oldest.Value.Token);
        }
    }

    // Value is null for a token that is never restored, such as a secret's. SecretHashes holds the keyed hash of each
    // value the token was registered with as a secret, usually one, and is null for a token never registered as one.
    private readonly record struct Entry(string Token, string? Value, DateTimeOffset LastUsed, string[]? SecretHashes = null)
    {
        public override string ToString() => Token;
    }
}
