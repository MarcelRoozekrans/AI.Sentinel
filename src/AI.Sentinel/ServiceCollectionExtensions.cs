using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

namespace AI.Sentinel;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        Action<SentinelOptions>? configure = null)
    {
        var opts = new SentinelOptions();
        configure?.Invoke(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAlertSink>(opts.AlertWebhook is not null
            ? new WebhookAlertSink(opts.AlertWebhook)
            : NullAlertSink.Instance);
        services.AddSingleton<IAuditStore>(new RingBufferAuditStore(opts.AuditCapacity));
        services.AddSingleton(sp => new InterventionEngine(
            opts,
            mediator: sp.GetService<IMediator>(),
            logger: sp.GetService<ILogger<InterventionEngine>>()));

        services.AddAISentinelDetectors();

        services.AddSingleton(sp =>
            new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>()));

        return services;
    }

    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder) =>
        builder.Use((inner, sp) => new SentinelChatClient(
            inner,
            sp.GetRequiredService<DetectionPipeline>(),
            sp.GetRequiredService<IAuditStore>(),
            sp.GetRequiredService<InterventionEngine>(),
            sp.GetRequiredService<SentinelOptions>(),
            sp.GetRequiredService<IAlertSink>()));

    public static SentinelPipeline BuildSentinelPipeline(
        this IServiceProvider sp,
        IChatClient innerClient)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        return new SentinelPipeline(
            innerClient,
            sp.GetRequiredService<DetectionPipeline>(),
            sp.GetRequiredService<IAuditStore>(),
            sp.GetRequiredService<InterventionEngine>(),
            sp.GetRequiredService<SentinelOptions>(),
            sp.GetRequiredService<IAlertSink>());
    }
}
