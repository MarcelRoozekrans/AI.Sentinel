using System.Text;
using AI.Sentinel.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.Profiles;

public sealed class SignedProfileTests
{
    internal static PolicyProfile Sample() => new()
    {
        Organisation = "acme",
        Repository = "github.com/acme/widgets",
        Node = "node-1",
        ConfigurationVersion = 42,
        ModuleHash = "sha256:abc",
        Module = "package sentinel\n\ndefault allow := false",
        FailMode = ProfileFailModes.Closed,
        SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["medium"] = "alert",
            ["critical"] = "quarantine",
            ["high"] = "block",
        },
        LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["audit"] = true,
            ["raw_text"] = false,
        },
        IssuedAt = new DateTimeOffset(2026, 11, 23, 10, 0, 0, TimeSpan.Zero),
        ExpiresAt = new DateTimeOffset(2026, 11, 30, 10, 0, 0, TimeSpan.Zero),
    };

    [Fact]
    public void Canonical_form_is_the_same_bytes_every_time()
    {
        var a = ProfileCanonicalJson.Serialize(Sample());
        var b = ProfileCanonicalJson.Serialize(Sample());
        Assert.Equal(a, b);
    }

    [Fact]
    public void Canonical_form_does_not_depend_on_dictionary_insertion_order()
    {
        var reordered = Sample() with
        {
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["high"] = "block",
                ["critical"] = "quarantine",
                ["medium"] = "alert",
            },
            LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal)
            {
                ["raw_text"] = false,
                ["audit"] = true,
            },
        };
        Assert.Equal(ProfileCanonicalJson.Serialize(Sample()), ProfileCanonicalJson.Serialize(reordered));
    }

    [Fact]
    public void Canonical_form_has_sorted_keys_no_whitespace_and_utc_seconds()
    {
        var json = Encoding.UTF8.GetString(ProfileCanonicalJson.Serialize(Sample()));
        Assert.Equal(
            "{\"configuration_version\":42,\"expires_at\":\"2026-11-30T10:00:00Z\",\"fail_mode\":\"closed\","
            + "\"issued_at\":\"2026-11-23T10:00:00Z\",\"logging\":{\"audit\":true,\"raw_text\":false},"
            + "\"module\":\"package sentinel\\n\\ndefault allow := false\",\"module_hash\":\"sha256:abc\","
            + "\"node\":\"node-1\",\"organisation\":\"acme\",\"repository\":\"github.com/acme/widgets\","
            + "\"severity_defaults\":{\"critical\":\"quarantine\",\"high\":\"block\",\"medium\":\"alert\"}}",
            json);
    }

    [Fact]
    public void Offsets_are_normalised_to_utc()
    {
        var local = Sample() with { IssuedAt = new DateTimeOffset(2026, 11, 23, 11, 0, 0, TimeSpan.FromHours(1)) };
        Assert.Equal(ProfileCanonicalJson.Serialize(Sample()), ProfileCanonicalJson.Serialize(local));
    }

    [Fact]
    public void Non_ascii_text_is_escaped_the_same_way_every_time()
    {
        var p = Sample() with { Module = "café 😀 <>&" };
        var json = Encoding.UTF8.GetString(ProfileCanonicalJson.Serialize(p));
        Assert.Contains("caf\\u00E9 \\uD83D\\uDE00 \\u003C\\u003E\\u0026", json, StringComparison.Ordinal);
        Assert.Equal(p.Module, ProfileCanonicalJson.Deserialize(ProfileCanonicalJson.Serialize(p))!.Module);
    }

    [Fact]
    public void Canonical_bytes_round_trip_to_the_same_profile_and_bytes()
    {
        var bytes = ProfileCanonicalJson.Serialize(Sample());
        var back = ProfileCanonicalJson.Deserialize(bytes);
        Assert.NotNull(back);
        Assert.Equal("acme", back.Organisation);
        Assert.Equal(42, back.ConfigurationVersion);
        Assert.Equal("quarantine", back.SeverityDefaults["critical"]);
        Assert.False(back.LoggingSwitches["raw_text"]);
        Assert.Equal(Sample().ExpiresAt, back.ExpiresAt);
        Assert.Equal(bytes, ProfileCanonicalJson.Serialize(back));
    }

    [Fact]
    public void Garbage_does_not_deserialize()
    {
        Assert.Null(ProfileCanonicalJson.Deserialize("not json"u8.ToArray()));
        Assert.Null(ProfileCanonicalJson.Deserialize("{}"u8.ToArray()));
    }
}
