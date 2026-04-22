namespace AI.Sentinel.Cli;

public static class BaselineDiffer
{
    public static (bool HasRegression, IReadOnlyList<DiffEntry> Entries) Diff(
        ReplayResult baseline,
        ReplayResult current)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);

        if (baseline.TurnCount != current.TurnCount)
            throw new InvalidDataException(
                $"Baseline has {baseline.TurnCount} turns but current has {current.TurnCount}.");

        var entries = new List<DiffEntry>();
        var baseMap = new Dictionary<string, TurnDetection>(StringComparer.Ordinal);
        var currentMap = new Dictionary<string, TurnDetection>(StringComparer.Ordinal);
        var hasRegression = false;

        for (var i = 0; i < baseline.TurnCount; i++)
        {
            baseMap.Clear();
            currentMap.Clear();
            foreach (var d in baseline.Turns[i].Detections) baseMap[d.DetectorId] = d;
            foreach (var d in current.Turns[i].Detections) currentMap[d.DetectorId] = d;

            if (DiffTurn(i, baseMap, currentMap, entries)) hasRegression = true;
        }

        return (hasRegression, entries);
    }

    private static bool DiffTurn(
        int turnIndex,
        Dictionary<string, TurnDetection> baseMap,
        Dictionary<string, TurnDetection> currentMap,
        List<DiffEntry> entries)
    {
        var hasRegression = false;

        foreach (var (id, baseDet) in baseMap)
        {
            if (!currentMap.TryGetValue(id, out var currentDet))
            {
                entries.Add(new DiffEntry(turnIndex, id, DiffKind.Regression,
                    $"{id} no longer fires (was {baseDet.Severity})"));
                hasRegression = true;
            }
            else if (currentDet.Severity < baseDet.Severity)
            {
                entries.Add(new DiffEntry(turnIndex, id, DiffKind.Changed,
                    $"{id} severity dropped {baseDet.Severity} -> {currentDet.Severity}"));
                hasRegression = true;
            }
        }

        foreach (var (id, currentDet) in currentMap)
        {
            if (!baseMap.ContainsKey(id))
                entries.Add(new DiffEntry(turnIndex, id, DiffKind.New,
                    $"{id} now fires ({currentDet.Severity})"));
        }

        return hasRegression;
    }
}
