using AI.Sentinel.Detection;
namespace AI.Sentinel.Intervention;

public sealed class SentinelException(string message, PipelineResult result)
    : Exception(message)
{
    public PipelineResult PipelineResult { get; } = result;
}
