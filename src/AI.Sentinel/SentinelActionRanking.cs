namespace AI.Sentinel;

internal static class SentinelActionRanking
{
    /// <summary>The most restrictive of <paramref name="actions"/>, ranked PassThrough, Log, Alert, Quarantine.
    /// Redact never reaches here: <see cref="SentinelOptions.EffectiveAction"/> has already resolved it.</summary>
    internal static SentinelAction MostRestrictive(IEnumerable<SentinelAction> actions)
    {
        var best = SentinelAction.PassThrough;
        foreach (var a in actions)
        {
            if (Rank(a) > Rank(best)) best = a;
        }
        return best;
    }

    private static int Rank(SentinelAction a) => a switch
    {
        SentinelAction.Log        => 1,
        SentinelAction.Alert      => 2,
        SentinelAction.Quarantine => 3,
        _                         => 0
    };
}
