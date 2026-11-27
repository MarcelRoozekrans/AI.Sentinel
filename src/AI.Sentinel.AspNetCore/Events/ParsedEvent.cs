namespace AI.Sentinel.AspNetCore.Events;

internal sealed class ParsedEvent
{
    public string? Id { get; set; }
    public DateTimeOffset? At { get; set; }
    public string? ToolKind { get; set; }
    public string? Outcome { get; set; }
    public List<string>? Policies { get; set; }
    public string? PolicyVersion { get; set; }
    public string? Decided { get; set; }
    public string? Node { get; set; }
    public string? Cli { get; set; }
    public string? Session { get; set; }
    public string? Detector { get; set; }
    public string? Severity { get; set; }
    public Dictionary<string, int> Redactions { get; set; } = new(StringComparer.Ordinal);
    public string? Reason { get; set; }
}
