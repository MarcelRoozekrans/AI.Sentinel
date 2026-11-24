using AI.Sentinel.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.Profiles;

public sealed class ProfileKeyPinningTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);
    private const string Org = "acme";
    private const string Repo = "github.com/acme/widgets";

    private static ProfileSigner SignerFor(ProfileSigningKeys keys) => new(keys, new FixedTime(Now));

    private static ProfileVerification Check(SignedProfile s, PinnedProfileKeys pins) =>
        ProfileVerifier.Verify(s, pins, Org, Repo, Now);

    [Fact]
    public void Keys_pinned_as_base64_round_trip()
    {
        var a = ProfileSigningKey.Generate();
        var b = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([a.PublicKey, b.PublicKey]);

        var again = PinnedProfileKeys.FromBase64(pins.ToBase64());

        Assert.Equal(2, again.Count);
        Assert.Equal(pins.ToBase64(), again.ToBase64());
        Assert.True(Check(SignerFor(new ProfileSigningKeys(b)).Issue(SignedProfileTests.Sample()), again).IsAccepted);
    }

    [Fact]
    public void A_pinned_key_that_is_not_32_bytes_is_refused()
    {
        Assert.Throws<ArgumentException>(() => PinnedProfileKeys.Create([new byte[5]]));
        Assert.Throws<FormatException>(() => PinnedProfileKeys.FromBase64(["not base64!"]));
    }

    [Fact]
    public void With_returns_a_new_set_and_leaves_the_old_one_alone()
    {
        var a = ProfileSigningKey.Generate();
        var b = ProfileSigningKey.Generate();
        var one = PinnedProfileKeys.Create([a.PublicKey]);
        var two = one.With(b.PublicKey);

        Assert.Equal(1, one.Count);
        Assert.Equal(2, two.Count);
    }

    [Fact]
    public void A_signing_key_comes_from_a_base64_seed_and_signs_the_same_as_the_raw_seed()
    {
        var seed = Ed25519Crypto.NewSeed();
        var fromText = ProfileSigningKey.FromBase64(Convert.ToBase64String(seed));
        var fromBytes = new ProfileSigningKey(seed);

        Assert.Equal(fromBytes.KeyId, fromText.KeyId);
        Assert.Equal(fromBytes.PublicKey, fromText.PublicKey);
        Assert.Throws<FormatException>(() => ProfileSigningKey.FromBase64("AAAA"));
        Assert.Throws<FormatException>(() => ProfileSigningKey.FromBase64("not base64!"));
    }

    [Fact]
    public void The_deployment_keys_are_read_from_base64_and_the_previous_one_may_be_empty()
    {
        var current = Convert.ToBase64String(Ed25519Crypto.NewSeed());
        var previous = Convert.ToBase64String(Ed25519Crypto.NewSeed());

        Assert.Null(ProfileSigningKeys.FromBase64(current).Previous);
        Assert.Null(ProfileSigningKeys.FromBase64(current, "").Previous);
        Assert.NotNull(ProfileSigningKeys.FromBase64(current, previous).Previous);
        Assert.Throws<ArgumentException>(() => ProfileSigningKeys.FromBase64(current, current));
    }

    [Fact]
    public void The_signer_has_no_way_to_hand_the_seed_back()
    {
        var members = typeof(ProfileSigningKey).GetMembers(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Select(m => m.Name)
            .ToList();
        Assert.DoesNotContain(members, n => n.Contains("Seed", StringComparison.OrdinalIgnoreCase)
            || n.Contains("Private", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void During_a_rotation_a_plugin_that_pinned_only_the_old_key_accepts_the_new_one()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var rotating = SignerFor(new ProfileSigningKeys(newKey, previous: oldKey));

        var result = Check(rotating.Issue(SignedProfileTests.Sample()), pins);

        Assert.True(result.IsAccepted);
        Assert.Equal(newKey.PublicKey, result.EndorsedKey);
    }

    [Fact]
    public void After_pinning_the_endorsed_key_profiles_verify_without_the_old_key()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var result = Check(SignerFor(new ProfileSigningKeys(newKey, oldKey)).Issue(SignedProfileTests.Sample()), pins);
        var updated = pins.With(result.EndorsedKey!);

        // The deployment drops the old key: no endorsement any more.
        var after = Check(SignerFor(new ProfileSigningKeys(newKey)).Issue(SignedProfileTests.Sample()), updated);

        Assert.True(after.IsAccepted);
        Assert.Null(after.EndorsedKey);
        Assert.Equal(ProfileRejection.UnknownKey, Check(SignerFor(new ProfileSigningKeys(newKey)).Issue(SignedProfileTests.Sample()), pins).Rejection);
    }

    [Fact]
    public void A_pinned_key_needs_no_endorsement()
    {
        var key = ProfileSigningKey.Generate();
        var result = Check(SignerFor(new ProfileSigningKeys(key)).Issue(SignedProfileTests.Sample()), PinnedProfileKeys.Create([key.PublicKey]));
        Assert.True(result.IsAccepted);
        Assert.Null(result.EndorsedKey);
    }

    [Fact]
    public void An_endorsement_by_a_key_that_is_not_pinned_is_refused()
    {
        var pinned = ProfileSigningKey.Generate();
        var stranger = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var signed = SignerFor(new ProfileSigningKeys(newKey, stranger)).Issue(SignedProfileTests.Sample());

        Assert.Equal(ProfileRejection.UnknownKey, Check(signed, PinnedProfileKeys.Create([pinned.PublicKey])).Rejection);
    }

    [Fact]
    public void An_endorsement_is_only_good_for_the_key_it_names()
    {
        var oldKey = ProfileSigningKey.Generate();
        var endorsedKey = ProfileSigningKey.Generate();
        var attacker = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var genuine = KeyEndorsement.Create(oldKey, endorsedKey);

        // The attacker signs with their own key and attaches the genuine endorsement of another key.
        var signed = SignerFor(new ProfileSigningKeys(attacker)).Issue(SignedProfileTests.Sample()) with { Endorsements = [genuine] };
        Assert.Equal(ProfileRejection.UnknownKey, Check(signed, pins).Rejection);

        // Or rewrites the endorsement to name their key id and public key while keeping the old signature.
        var rewritten = genuine with { KeyId = attacker.KeyId, PublicKey = Convert.ToBase64String(attacker.PublicKey) };
        var signed2 = SignerFor(new ProfileSigningKeys(attacker)).Issue(SignedProfileTests.Sample()) with { Endorsements = [rewritten] };
        Assert.Equal(ProfileRejection.UnknownKey, Check(signed2, pins).Rejection);
    }

    [Fact]
    public void An_endorsement_whose_key_id_does_not_match_its_public_key_is_refused()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var other = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var lie = KeyEndorsement.Create(oldKey, other) with { KeyId = newKey.KeyId };
        var signed = SignerFor(new ProfileSigningKeys(newKey)).Issue(SignedProfileTests.Sample()) with { Endorsements = [lie] };

        Assert.Equal(ProfileRejection.UnknownKey, Check(signed, pins).Rejection);
    }

    [Fact]
    public void An_endorsed_key_cannot_endorse_another_key()
    {
        var root = ProfileSigningKey.Generate();
        var middle = ProfileSigningKey.Generate();
        var leaf = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([root.PublicKey]);
        var signed = SignerFor(new ProfileSigningKeys(leaf, middle)).Issue(SignedProfileTests.Sample())
            with
        { Endorsements = [KeyEndorsement.Create(middle, leaf), KeyEndorsement.Create(root, middle)] };

        Assert.Equal(ProfileRejection.UnknownKey, Check(signed, pins).Rejection);
    }

    [Fact]
    public void A_damaged_endorsement_is_refused()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var signed = SignerFor(new ProfileSigningKeys(newKey, oldKey)).Issue(SignedProfileTests.Sample());
        var sig = Convert.FromBase64String(signed.Endorsements[0].Signature);
        sig[3] ^= 0x01;

        var broken = signed with { Endorsements = [signed.Endorsements[0] with { Signature = Convert.ToBase64String(sig) }] };
        var garbled = signed with { Endorsements = [signed.Endorsements[0] with { PublicKey = "!!!" }] };

        Assert.Equal(ProfileRejection.UnknownKey, Check(broken, pins).Rejection);
        Assert.Equal(ProfileRejection.UnknownKey, Check(garbled, pins).Rejection);
    }

    [Fact]
    public void An_endorsed_profile_still_gets_every_other_check()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var signed = SignerFor(new ProfileSigningKeys(newKey, oldKey)).Issue(SignedProfileTests.Sample());

        Assert.Equal(ProfileRejection.Expired, ProfileVerifier.Verify(signed, pins, Org, Repo, Now.AddDays(8)).Rejection);
        Assert.Equal(ProfileRejection.OrganisationMismatch, ProfileVerifier.Verify(signed, pins, "other", Repo, Now).Rejection);
        var bytes = Convert.FromBase64String(signed.Profile);
        bytes[5] ^= 0x01;
        Assert.Equal(ProfileRejection.BadSignature, Check(signed with { Profile = Convert.ToBase64String(bytes) }, pins).Rejection);
    }

    [Fact]
    public void Endorsements_survive_the_cache_round_trip()
    {
        var oldKey = ProfileSigningKey.Generate();
        var newKey = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([oldKey.PublicKey]);
        var json = SignerFor(new ProfileSigningKeys(newKey, oldKey)).Issue(SignedProfileTests.Sample()).ToJson();

        var cached = SignedProfile.Parse(json)!;

        Assert.Single(cached.Endorsements);
        Assert.True(Check(cached, pins).IsAccepted);
        Assert.Null(SignedProfile.Parse(json.Replace("\"endorsements\":[{", "\"endorsements\":[null,{", StringComparison.Ordinal)));
        var explicitNull = SignedProfile.Parse(json.Replace("\"endorsements\":[{", "\"endorsements\":null,\"x\":[{", StringComparison.Ordinal));
        Assert.Null(explicitNull);
    }

    [Fact]
    public void An_envelope_from_before_rotation_support_has_no_endorsements()
    {
        var key = ProfileSigningKey.Generate();
        var json = SignerFor(new ProfileSigningKeys(key)).Issue(SignedProfileTests.Sample()).ToJson();
        var explicitNullJson = json.Replace("\"endorsements\":[]", "\"endorsements\":null", StringComparison.Ordinal);
        Assert.Empty(SignedProfile.Parse(explicitNullJson)!.Endorsements);
        var withoutField = json.Replace(",\"endorsements\":[]", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("endorsements", withoutField, StringComparison.Ordinal);

        var parsed = SignedProfile.Parse(withoutField);
        Assert.NotNull(parsed);
        Assert.Empty(parsed.Endorsements);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
