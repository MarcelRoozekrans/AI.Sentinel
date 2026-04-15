using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Mediator;
namespace AI.Sentinel.Intervention;

public readonly record struct InterventionAppliedNotification(
    SessionId SessionId,
    SentinelAction Action,
    Severity Severity,
    string Reason,
    DateTimeOffset AppliedAt) : INotification;
