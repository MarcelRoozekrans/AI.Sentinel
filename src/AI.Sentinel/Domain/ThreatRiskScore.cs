namespace AI.Sentinel.Domain;

public readonly struct ThreatRiskScore(int raw) : IEquatable<ThreatRiskScore>
{
    public int Value { get; } = Math.Clamp(raw, 0, 100);

    public ThreatStage Stage => Value switch
    {
        < 25  => ThreatStage.Safe,
        < 50  => ThreatStage.Watch,
        < 75  => ThreatStage.Alert,
        _     => ThreatStage.Isolate
    };

    public static readonly ThreatRiskScore Zero = new(0);

    public static ThreatRiskScore Aggregate(IEnumerable<ThreatRiskScore> scores)
    {
        int max = 0, sum = 0, count = 0;
        foreach (var s in scores)
        {
            max = Math.Max(max, s.Value);
            sum += s.Value;
            count++;
        }
        if (count == 0) return Zero;
        return new((int)(max * 0.6 + (sum / count) * 0.4));
    }

    public bool Equals(ThreatRiskScore other) => Value == other.Value;
    public override bool Equals(object? obj) => obj is ThreatRiskScore other && Equals(other);
    public override int GetHashCode() => Value;
    public static bool operator ==(ThreatRiskScore left, ThreatRiskScore right) => left.Equals(right);
    public static bool operator !=(ThreatRiskScore left, ThreatRiskScore right) => !left.Equals(right);
    public override string ToString() => Value.ToString();
}
