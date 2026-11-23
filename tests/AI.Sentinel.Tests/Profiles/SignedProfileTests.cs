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
        var json = Encoding.UTF8.GetString(ProfileCanonicalJson.Serialize(Sample()));
        Assert.Null(ProfileCanonicalJson.Deserialize(Encoding.UTF8.GetBytes(json.Replace("\"fail_mode\":\"closed\"", "\"fail_mode\":\"maybe\"", StringComparison.Ordinal))));
        Assert.Null(ProfileCanonicalJson.Deserialize(Encoding.UTF8.GetBytes(json.Replace("\"module_hash\":\"sha256:abc\"", "\"module_hash\":null", StringComparison.Ordinal))));
        Assert.Null(ProfileCanonicalJson.Deserialize(Encoding.UTF8.GetBytes(json.Replace("\"expires_at\":\"2026-11-30T10:00:00Z\"", "\"expires_at\":\"2026-11-20T10:00:00Z\"", StringComparison.Ordinal))));
        Assert.Null(ProfileCanonicalJson.Deserialize(Encoding.UTF8.GetBytes(json.Replace("{\"c", "{\"extra\":1,\"c", StringComparison.Ordinal))));
    }

    private static readonly DateTimeOffset Now = new(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);

    private static (ProfileSigner Signer, PinnedProfileKeys Pins) Server(TimeSpan? offset = null)
    {
        var key = ProfileSigningKey.Generate();
        var time = new FakeTime(Now + (offset ?? TimeSpan.Zero));
        return (new ProfileSigner(key, time), PinnedProfileKeys.Create([key.PublicKey]));
    }

    private static ProfileVerification Check(SignedProfile s, PinnedProfileKeys pins, DateTimeOffset? at = null,
        string org = "acme", string repo = "github.com/acme/widgets") =>
        ProfileVerifier.Verify(s, pins, org, repo, at ?? Now);

    [Fact]
    public void A_profile_signed_by_a_pinned_key_is_accepted_and_comes_back_intact()
    {
        var (signer, pins) = Server();
        var signed = signer.Issue(Sample());

        var result = Check(signed, pins);

        Assert.True(result.IsAccepted);
        Assert.Equal(ProfileRejection.None, result.Rejection);
        Assert.Equal("node-1", result.Profile!.Node);
        Assert.Equal(Now, result.Profile.IssuedAt);
    }

    [Fact]
    public void The_same_profile_signs_to_the_same_signature()
    {
        var key = ProfileSigningKey.Generate();
        var signer = new ProfileSigner(key);
        Assert.Equal(signer.Sign(Sample()), signer.Sign(Sample()));
    }

    [Fact]
    public void The_default_lifetime_is_seven_days()
    {
        Assert.Equal(TimeSpan.FromDays(7), ProfileSigner.DefaultLifetime);
        var (signer, pins) = Server();
        var profile = Check(signer.Issue(Sample()), pins).Profile!;
        Assert.Equal(Now.AddDays(7), profile.ExpiresAt);
    }

    [Fact]
    public void An_organisation_can_set_its_own_lifetime()
    {
        var (signer, pins) = Server();
        var profile = Check(signer.Issue(Sample(), TimeSpan.FromHours(12)), pins).Profile!;
        Assert.Equal(Now.AddHours(12), profile.ExpiresAt);
    }

    [Fact]
    public void A_lifetime_under_a_second_is_refused()
    {
        var (signer, _) = Server();
        Assert.Throws<ArgumentOutOfRangeException>(() => signer.Issue(Sample(), TimeSpan.Zero));
    }

    [Fact]
    public void A_profile_stays_usable_until_it_expires_and_not_after()
    {
        var (signer, pins) = Server();
        var signed = signer.Issue(Sample());
        Assert.True(Check(signed, pins, Now.AddDays(7).AddSeconds(-1)).IsAccepted);
        Assert.Equal(ProfileRejection.Expired, Check(signed, pins, Now.AddDays(7)).Rejection);
        Assert.Equal(ProfileRejection.Expired, Check(signed, pins, Now.AddDays(30)).Rejection);
    }

    [Fact]
    public void A_signature_from_a_key_that_is_not_pinned_is_refused()
    {
        var (_, pins) = Server();
        var stranger = new ProfileSigner(ProfileSigningKey.Generate());
        Assert.Equal(ProfileRejection.UnknownKey, Check(stranger.Issue(Sample()), pins).Rejection);
    }

    [Fact]
    public void A_signature_from_another_key_under_a_pinned_key_id_is_refused()
    {
        var (_, pins) = Server();
        var pinnedId = ProfileKeyId.Of(PinnedPublicKey(pins));
        var forged = new ProfileSigner(ProfileSigningKey.Generate()).Issue(Sample()) with { KeyId = pinnedId };
        Assert.Equal(ProfileRejection.BadSignature, Check(forged, pins).Rejection);
    }

    [Fact]
    public void A_changed_byte_is_refused()
    {
        var (signer, pins) = Server();
        var signed = signer.Issue(Sample());
        var bytes = Convert.FromBase64String(signed.Profile);
        bytes[bytes.Length / 2] ^= 0x01;
        var tampered = signed with { Profile = Convert.ToBase64String(bytes) };

        Assert.Equal(ProfileRejection.BadSignature, Check(tampered, pins).Rejection);
    }

    [Fact]
    public void A_changed_signature_byte_is_refused()
    {
        var (signer, pins) = Server();
        var signed = signer.Issue(Sample());
        var sig = Convert.FromBase64String(signed.Signature);
        sig[10] ^= 0x01;

        Assert.Equal(ProfileRejection.BadSignature, Check(signed with { Signature = Convert.ToBase64String(sig) }, pins).Rejection);
    }

    [Fact]
    public void A_profile_for_another_organisation_is_refused()
    {
        var (signer, pins) = Server();
        Assert.Equal(ProfileRejection.OrganisationMismatch, Check(signer.Issue(Sample()), pins, org: "other").Rejection);
    }

    [Fact]
    public void A_profile_for_another_repository_is_refused()
    {
        var (signer, pins) = Server();
        Assert.Equal(ProfileRejection.RepositoryMismatch, Check(signer.Issue(Sample()), pins, repo: "github.com/acme/other").Rejection);
    }

    [Fact]
    public void Garbled_envelopes_are_refused_as_malformed()
    {
        var (signer, pins) = Server();
        var signed = signer.Issue(Sample());
        Assert.Equal(ProfileRejection.Malformed, Check(signed with { Profile = "!!!" }, pins).Rejection);
        Assert.Equal(ProfileRejection.Malformed, Check(signed with { Signature = "!!!" }, pins).Rejection);
    }

    [Fact]
    public void Signed_bytes_that_are_not_canonical_are_refused_as_malformed()
    {
        var key = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([key.PublicKey]);
        var loose = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(ProfileCanonicalJson.Serialize(Sample())).Replace("{\"c", "{ \"c", StringComparison.Ordinal));
        var signed = new SignedProfile
        {
            Profile = Convert.ToBase64String(loose),
            KeyId = key.KeyId,
            Signature = Convert.ToBase64String(key.Sign(loose)),
        };

        Assert.Equal(ProfileRejection.Malformed, Check(signed, pins).Rejection);
    }

    [Fact]
    public void A_cached_profile_is_used_offline_until_it_expires()
    {
        var (signer, pins) = Server();
        var cached = SignedProfile.Parse(signer.Issue(Sample()).ToJson())!;
        Assert.True(Check(cached, pins, Now.AddDays(6)).IsAccepted);
        Assert.Equal(ProfileRejection.Expired, Check(cached, pins, Now.AddDays(8)).Rejection);
    }

    [Fact]
    public void A_cache_that_fails_its_signature_check_is_unusable()
    {
        var (signer, pins) = Server();
        var json = signer.Issue(Sample()).ToJson();
        var damaged = SignedProfile.Parse(json.Replace("\"signature\":\"", "\"signature\":\"A", StringComparison.Ordinal));
        Assert.NotNull(damaged);
        Assert.False(Check(damaged, pins).IsAccepted);
    }

    [Fact]
    public void Text_that_is_not_an_envelope_does_not_parse()
    {
        Assert.Null(SignedProfile.Parse("nope"));
        Assert.Null(SignedProfile.Parse("{}"));
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("key_id")]
    [InlineData("signature")]
    public void An_envelope_with_a_null_member_does_not_parse(string member)
    {
        var (signer, _) = Server();
        var json = System.Text.Json.Nodes.JsonNode.Parse(signer.Issue(Sample()).ToJson())!.AsObject();
        json[member] = null;

        Assert.Null(SignedProfile.Parse(json.ToJsonString()));
    }

    [Fact]
    public void A_signed_profile_with_a_null_severity_action_is_refused_as_malformed()
    {
        var (signer, pins) = Server();
        var profile = Sample() with
        {
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal) { ["high"] = null! },
        };

        Assert.Equal(ProfileRejection.Malformed, Check(signer.Issue(profile), pins).Rejection);
    }

    [Fact]
    public void No_pinned_keys_means_no_profile_is_accepted()
    {
        var signer = new ProfileSigner(ProfileSigningKey.Generate());
        Assert.Equal(ProfileRejection.UnknownKey, Check(signer.Issue(Sample()), PinnedProfileKeys.Empty).Rejection);
    }

    [Fact]
    public void A_signing_key_never_prints_its_seed()
    {
        var seed = Ed25519Crypto.NewSeed();
        var key = new ProfileSigningKey(seed);
        Assert.DoesNotContain(Convert.ToBase64String(seed), key.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexStringLower(seed), key.ToString(), StringComparison.Ordinal);
    }

    private static byte[] PinnedPublicKey(PinnedProfileKeys pins) => Convert.FromBase64String(pins.ToBase64()[0]);

    private sealed class FakeTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
