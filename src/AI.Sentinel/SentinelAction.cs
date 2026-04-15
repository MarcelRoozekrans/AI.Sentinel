namespace AI.Sentinel;

public enum SentinelAction
{
    /// <summary>
    /// Allow the message through with no logging or notification.
    /// No mediator notification is published.
    /// </summary>
    PassThrough,

    /// <summary>
    /// Allow the message through and publish mediator notifications
    /// (<see cref="Intervention.ThreatDetectedNotification"/> and
    /// <see cref="Intervention.InterventionAppliedNotification"/>).
    /// Wire up notification handlers in the consuming application to record, aggregate, or forward events.
    /// </summary>
    Log,

    /// <summary>
    /// Allow the message through and publish mediator notifications, identical to <see cref="Log"/>.
    /// By convention, <c>Alert</c> signals that the consuming application's notification handlers
    /// should take an active alerting action (e.g. page on-call, send a Slack message).
    /// The distinction from <see cref="Log"/> is enforced by the handlers you register, not by AI.Sentinel itself.
    /// </summary>
    Alert,

    /// <summary>
    /// Block the message by throwing <see cref="Intervention.SentinelException"/>.
    /// Mediator notifications are still published before the exception is thrown.
    /// </summary>
    Quarantine
}
