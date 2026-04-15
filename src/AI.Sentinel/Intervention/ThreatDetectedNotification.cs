using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Mediator;
namespace AI.Sentinel.Intervention;

public readonly record struct ThreatDetectedNotification(
    SessionId SessionId,
    AgentId SenderId,
    AgentId ReceiverId,
    PipelineResult Result,
    DateTimeOffset DetectedAt) : INotification;
