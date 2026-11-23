using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AI.Sentinel.Profiles;

/// <summary>
/// The canonical JSON form of a <see cref="PolicyProfile"/>: the bytes the server signs and the plugin verifies.
/// The same profile always gives the same bytes.
/// <list type="bullet">
/// <item>One JSON object, UTF-8, no byte order mark, no insignificant whitespace.</item>
/// <item>Keys sorted by ordinal comparison, at the top level and inside <c>severity_defaults</c> and <c>logging</c>.</item>
/// <item>Strings escaped by the default System.Text.Json encoder: every non-ASCII character and <c>&lt; &gt; &amp;</c>
/// as an uppercase <c>\uXXXX</c> escape, so no text has two spellings.</item>
/// <item>Integers in plain decimal. Times as UTC to the whole second, <c>yyyy-MM-ddTHH:mm:ssZ</c>; a fraction of a
/// second is dropped.</item>
/// <item>Booleans as <c>true</c> and <c>false</c>. No null: every member is required.</item>
/// </list>
/// Reading is by the source-generated <see cref="ProfileJsonContext"/>; a verifier calls
/// <see cref="IsCanonical"/> so bytes that parse but are not in this form are refused.
/// </summary>
internal static class ProfileCanonicalJson
{
    private const string TimeFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.Default,
        SkipValidation = false,
    };

    /// <summary>The canonical bytes of <paramref name="profile"/>.</summary>
    public static byte[] Serialize(PolicyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream, WriterOptions))
        {
            w.WriteStartObject();
            w.WriteNumber("configuration_version", profile.ConfigurationVersion);
            w.WriteString("expires_at", Time(profile.ExpiresAt));
            w.WriteString("fail_mode", profile.FailMode);
            w.WriteString("issued_at", Time(profile.IssuedAt));
            w.WriteStartObject("logging");
            foreach (var kv in Sorted(profile.LoggingSwitches))
            {
                w.WriteBoolean(kv.Key, kv.Value);
            }
            w.WriteEndObject();
            w.WriteString("module", profile.Module);
            w.WriteString("module_hash", profile.ModuleHash);
            w.WriteString("node", profile.Node);
            w.WriteString("organisation", profile.Organisation);
            w.WriteString("repository", profile.Repository);
            w.WriteStartObject("severity_defaults");
            foreach (var kv in Sorted(profile.SeverityDefaults))
            {
                w.WriteString(kv.Key, kv.Value);
            }
            w.WriteEndObject();
            w.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>
    /// Reads a profile. Returns null when the bytes are not a complete, valid profile: bad JSON, a missing or unknown
    /// member, an unknown fail mode, an empty identity or an expiry that is not after the issue time.
    /// </summary>
    public static PolicyProfile? Deserialize(ReadOnlySpan<byte> utf8)
    {
        PolicyProfile? profile;
        try
        {
            profile = JsonSerializer.Deserialize(utf8, ProfileJsonContext.Default.PolicyProfile);
        }
        catch (JsonException)
        {
            return null;
        }
        return profile is not null && IsValid(profile) ? profile : null;
    }

    /// <summary>True when <paramref name="utf8"/> is exactly the canonical form of <paramref name="profile"/>.</summary>
    public static bool IsCanonical(ReadOnlySpan<byte> utf8, PolicyProfile profile) =>
        utf8.SequenceEqual(Serialize(profile));

    private static bool IsValid(PolicyProfile p) =>
        !string.IsNullOrEmpty(p.Organisation)
        && !string.IsNullOrEmpty(p.Repository)
        && !string.IsNullOrEmpty(p.Node)
        && p.Module is not null
        && p.ModuleHash is not null
        && p.SeverityDefaults is not null
        && p.LoggingSwitches is not null
        && ProfileFailModes.IsValid(p.FailMode)
        && p.ExpiresAt > p.IssuedAt;

    private static string Time(DateTimeOffset value) =>
        value.UtcDateTime.ToString(TimeFormat, CultureInfo.InvariantCulture);

    private static IEnumerable<KeyValuePair<string, T>> Sorted<T>(IReadOnlyDictionary<string, T> map) =>
        map.OrderBy(kv => kv.Key, StringComparer.Ordinal);
}
