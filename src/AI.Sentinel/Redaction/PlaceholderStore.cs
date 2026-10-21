using System.Buffers;
using System.Text.Json;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Redaction;

/// <summary>
/// The placeholders a long-lived host, such as the MCP proxy, minted across its calls, so a later tool call can get
/// the PII it names back in its arguments. Each call still redacts with its own <see cref="RedactionSession"/> and
/// tag, and registers what it minted here. Only values that may go into tool arguments are restored; a secret's
/// token is known, so a scan does not flag it, but its value is not kept. An entry expires after it has not been
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
    /// call. A poisoned token stays known, and literal, until it expires or is evicted.
    /// </summary>
    public void Register(IReadOnlyList<MintedPlaceholder> minted)
    {
        ArgumentNullException.ThrowIfNull(minted);
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            PurgeExpiredLocked(now);
            foreach (var m in minted)
            {
                // A secret's value is not kept: it is never restored, so only its token is needed.
                var value = m.RestoreIntoToolArguments ? m.Value : null;
                if (_byToken.TryGetValue(m.Token, out var node))
                {
                    // Kept only while both registrations are restorable and agree on the value; otherwise null for good.
                    var stored = node.Value.Value;
                    var kept = stored is not null && value is not null && string.Equals(stored, value, StringComparison.Ordinal)
                        ? stored
                        : null;
                    _byUse.Remove(node);
                    node.Value = new Entry(m.Token, kept, now);
                    _byUse.AddLast(node);
                    continue;
                }

                _byToken[m.Token] = _byUse.AddLast(new Entry(m.Token, value, now));
            }

            while (_byToken.Count > _maxEntries && _byUse.First is { } oldest)
            {
                _byUse.RemoveFirst();
                _byToken.Remove(oldest.Value.Token);
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
            _byUse.RemoveFirst();
            _byToken.Remove(oldest.Value.Token);
        }
    }

    // Value is null for a token that is never restored, such as a secret's.
    private readonly record struct Entry(string Token, string? Value, DateTimeOffset LastUsed)
    {
        public override string ToString() => Token;
    }
}
