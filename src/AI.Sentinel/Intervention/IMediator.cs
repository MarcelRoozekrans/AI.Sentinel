using ZeroAlloc.Mediator;
namespace AI.Sentinel.Intervention;

/// <summary>
/// Minimal mediator abstraction used by <see cref="InterventionEngine"/> to publish
/// sentinel notifications. Implement with ZeroAlloc.Mediator's generated MediatorService
/// in consuming applications, or provide a custom implementation.
/// </summary>
public interface IMediator
{
    ValueTask Publish<TNotification>(TNotification notification, CancellationToken ct = default)
        where TNotification : INotification;
}
