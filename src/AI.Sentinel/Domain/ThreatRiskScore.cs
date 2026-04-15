namespace AI.Sentinel.Domain;

public enum ThreatStage { Safe, Watch, Alert, Isolate }

public readonly struct ThreatRiskScore(int raw)
{
    public int Value { get; } = Math.Clamp(raw, 0, 100);

    public ThreatStage Stage => Value switch
    {
        < 25 => ThreatStage.Safe,
        < 50 => ThreatStage.Watch,
        < 75 => ThreatStage.Alert,
        _    => ThreatStage.Isolate
    };

    public static ThreatRiskScore Zero => new(0);

    public static ThreatRiskScore Aggregate(IEnumerable<int> scores)
    {
        int max = 0, sum = 0, count = 0;
        foreach (var s in scores) { max = Math.Max(max, s); sum += s; count++; }
        if (count == 0) return Zero;
        // weighted: 60% max severity + 40% average
        return new((int)(max * 0.6 + (sum / count) * 0.4));
    }
}
