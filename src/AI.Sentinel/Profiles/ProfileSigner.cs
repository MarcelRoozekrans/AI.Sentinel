namespace AI.Sentinel.Profiles;

/// <summary>The server side: issues a <see cref="PolicyProfile"/> and signs its canonical form with Ed25519.</summary>
internal sealed class ProfileSigner
{
    /// <summary>How long a profile lives unless the organisation sets another lifetime: 7 days.</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(7);

    private readonly ProfileSigningKey _key;
    private readonly TimeProvider _time;

    /// <summary>Signs with <paramref name="key"/>, which the deployment provided at startup.</summary>
    public ProfileSigner(ProfileSigningKey key, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Sets the issue time to now and the expiry to now plus <paramref name="lifetime"/> (default
    /// <see cref="DefaultLifetime"/>), both to the whole second, then signs. The times already on
    /// <paramref name="profile"/> are replaced.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The lifetime is shorter than one second.</exception>
    public SignedProfile Issue(PolicyProfile profile, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var life = lifetime ?? DefaultLifetime;
        ArgumentOutOfRangeException.ThrowIfLessThan(life, TimeSpan.FromSeconds(1), nameof(lifetime));
        var now = _time.GetUtcNow();
        var issued = new DateTimeOffset(now.Ticks - (now.Ticks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
        return Sign(profile with { IssuedAt = issued, ExpiresAt = issued + life });
    }

    /// <summary>Signs <paramref name="profile"/> as it is.</summary>
    public SignedProfile Sign(PolicyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var bytes = ProfileCanonicalJson.Serialize(profile);
        return new SignedProfile
        {
            Profile = Convert.ToBase64String(bytes),
            KeyId = _key.KeyId,
            Signature = Convert.ToBase64String(_key.Sign(bytes)),
        };
    }
}
