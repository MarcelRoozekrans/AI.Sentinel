namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What <see cref="ProfileRefresher.OfferAsync"/> did with a profile.</summary>
internal enum ProfileOffer
{
    /// <summary>It was verified, written to the cache and made the warm module.</summary>
    Installed,

    /// <summary>It is not newer than the one in force, so nothing changed. That is not a failure.</summary>
    Stale,

    /// <summary>It failed the check or its module did not load, so the profile in force stays.</summary>
    Refused,
}
