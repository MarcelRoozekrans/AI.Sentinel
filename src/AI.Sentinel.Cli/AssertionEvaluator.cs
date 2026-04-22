using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public static class AssertionEvaluator
{
    public static (bool Passed, IReadOnlyList<string> Failures) Evaluate(
        ReplayResult result,
        IReadOnlyList<string> expectedDetectors,
        Severity? minSeverity)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(expectedDetectors);

        var failures = new List<string>();

        foreach (var expected in expectedDetectors)
        {
            var fired = false;
            foreach (var turn in result.Turns)
            {
                foreach (var d in turn.Detections)
                {
                    if (string.Equals(d.DetectorId, expected, StringComparison.Ordinal))
                    {
                        fired = true;
                        break;
                    }
                }
                if (fired) break;
            }
            if (!fired)
                failures.Add($"Expected detector {expected} did not fire.");
        }

        if (minSeverity is Severity min && result.MaxSeverity < min)
            failures.Add($"Max severity {result.MaxSeverity} below required {min}.");

        return (failures.Count == 0, failures);
    }
}
