using System.Text.Json;

namespace AI.Sentinel.Cli.Report;

/// <summary>Renders a <see cref="ComplianceReport"/> as JSON, the shape a scheduled job or another tool reads.</summary>
internal static class JsonReportRenderer
{
    /// <summary>Renders the report as indented, camelCase JSON with <c>schema</c> set.</summary>
    /// <param name="report">The report to render.</param>
    internal static string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, ComplianceReportJsonContext.Default.ComplianceReport) + Environment.NewLine;
    }
}
