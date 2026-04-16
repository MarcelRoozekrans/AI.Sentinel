using AI.Sentinel.Detection;
namespace AI.Sentinel.Intervention;

public sealed class SentinelException : Exception
{
    public PipelineResult PipelineResult { get; } = default!;

    public SentinelException() { }
    public SentinelException(string message) : base(message) { }
    public SentinelException(string message, Exception innerException) : base(message, innerException) { }
    public SentinelException(string message, PipelineResult result) : base(message)
        => PipelineResult = result;
}
