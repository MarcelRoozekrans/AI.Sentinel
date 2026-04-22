using System.Globalization;
using System.Text;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public static class TextFormatter
{
    public static string Format(ReplayResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var sb = new StringBuilder();
        sb.Append("Scanned: ").Append(result.File)
          .Append(" (").Append(result.Format.ToString().ToLowerInvariant())
          .Append(", ").Append(result.TurnCount.ToString(CultureInfo.InvariantCulture))
          .AppendLine(" turns)");
        sb.AppendLine("-------------------------------------------");

        var totalDetections = 0;
        foreach (var turn in result.Turns)
        {
            if (turn.MaxSeverity == Severity.None)
            {
                sb.Append("Turn ").Append((turn.Index + 1).ToString(CultureInfo.InvariantCulture))
                  .AppendLine(": Clean");
                continue;
            }

            sb.Append("Turn ").Append((turn.Index + 1).ToString(CultureInfo.InvariantCulture))
              .Append(": ").AppendLine(turn.MaxSeverity.ToString().ToUpperInvariant());
            foreach (var d in turn.Detections)
            {
                sb.Append("  ").Append(d.DetectorId).Append(' ').AppendLine(d.Reason);
                totalDetections++;
            }
        }

        sb.AppendLine();
        sb.Append("Summary: ").Append(result.TurnCount.ToString(CultureInfo.InvariantCulture))
          .Append(" turns, ")
          .Append(totalDetections.ToString(CultureInfo.InvariantCulture))
          .Append(" detections, max severity ")
          .AppendLine(result.MaxSeverity.ToString().ToUpperInvariant());

        return sb.ToString();
    }
}
