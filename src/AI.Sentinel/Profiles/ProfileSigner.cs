namespace AI.Sentinel.Profiles;

/// <summary>The server side: issues a <see cref="PolicyProfile"/> and signs its canonical form with Ed25519.</summary>
internal sealed class ProfileSigner
{
    /// <summary>How long a profile lives unless the organisation sets another lifetime: 7 days.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(7);

    /// <summary>The latest expiry a profile gets: the last whole second a <see cref="DateTimeOffset"/> can hold.</summary>
    internal static readonly DateTimeOffset LatestExpiry = new(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);

    private readonly ProfileSigningKeys _keys;
    private readonly IReadOnlyList<KeyEndorsement> _endorsements;
    private readonly TimeProvider _time;

    /// <summary>Signs with the keys the deployment provided at startup.</summary>
    public ProfileSigner(ProfileSigningKeys keys, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(keys);
        _keys = keys;
        _endorsements = keys.Previous is null ? [] : [KeyEndorsement.Create(keys.Previous, keys.Current)];
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Signs with one key and no rotation under way.</summary>
    public ProfileSigner(ProfileSigningKey key, TimeProvider? time = null)
        : this(new ProfileSigningKeys(key), time)
    {
    }

    /// <summary>
    /// Sets the issue time to now and the expiry to now plus <paramref name="lifetime"/> (default
    /// <see cref="DefaultLifetime"/>), both to the whole second, then signs. The times already on
    /// <paramref name="profile"/> are replaced. A lifetime that would end after <see cref="LatestExpiry"/> ends there.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The lifetime is shorter than one second.</exception>
    public SignedProfile Issue(PolicyProfile profile, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var life = lifetime ?? DefaultLifetime;
        ArgumentOutOfRangeException.ThrowIfLessThan(life, TimeSpan.FromSeconds(1), nameof(lifetime));
        var now = _time.GetUtcNow();
        var issued = new DateTimeOffset(now.Ticks - (now.Ticks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
        // A lifetime that runs past the last representable time ends there, so the sum never overflows and the profile stays valid.
        var expires = life >= LatestExpiry - issued ? LatestExpiry : issued + life;
        return Sign(profile with { IssuedAt = issued, ExpiresAt = expires });
    }

    /// <summary>Signs <paramref name="profile"/> as it is. During a rotation the envelope carries the endorsement of the signing key.</summary>
    public SignedProfile Sign(PolicyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var bytes = ProfileCanonicalJson.Serialize(profile);
        return new SignedProfile
        {
            Profile = Convert.ToBase64String(bytes),
            KeyId = _keys.Current.KeyId,
            Signature = Convert.ToBase64String(_keys.Current.Sign(bytes)),
            Endorsements = _endorsements,
        };
    }
}
