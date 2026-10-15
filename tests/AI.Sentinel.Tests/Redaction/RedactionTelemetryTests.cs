using System.Diagnostics;
using System.Diagnostics.Metrics;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>
/// A pure redaction is not a threat. The ai.sentinel meter and activity source are process-wide statics,
/// so these exact-count assertions run in the NonParallel collection, alone, never beside detection tests.
/// </summary>
[Collection("NonParallel")]
public class RedactionTelemetryTests
{
    private sealed class RecordingAlertSink : IAlertSink
    {
        public int Calls;

        public ValueTask SendAsync(SentinelError error, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task PureRedaction_MovesNoThreatsCounter_NoAlert_NoThreatSpanTags()
    {
        var threats = 0L;
        var scans = new List<Activity>();
        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (instrument, l) =>
        {
            if (string.Equals(instrument.Meter.Name, "ai.sentinel", StringComparison.Ordinal) &&
                string.Equals(instrument.Name, "sentinel.threats", StringComparison.Ordinal))
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((_, measurement, _, _) => Interlocked.Add(ref threats, measurement));
        meterListener.Start();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => string.Equals(s.Name, "ai.sentinel", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a =>
            {
                lock (scans)
                {
                    if (string.Equals(a.OperationName, "sentinel.scan", StringComparison.Ordinal))
                    {
                        scans.Add(a);
                    }
                }
            },
        };
        ActivitySource.AddActivityListener(activityListener);
        var alerts = new RecordingAlertSink();
        var h = RedactionPipelineTests.Build("S", RedactionPipelineTests.RecordingModel.Echo(), services: sc =>
            sc.AddSingleton<IAlertSink>(alerts));

        await h.Client.GetResponseAsync(
            [new Microsoft.Extensions.AI.ChatMessage(Microsoft.Extensions.AI.ChatRole.User, "Mail jan@acme.nl please.")],
            null, TestContext.Current.CancellationToken);

        Assert.Equal(0, Interlocked.Read(ref threats));
        // WebhookAlertSink is an IAlertSink, so this also proves nothing is posted to the webhook.
        Assert.Equal(0, alerts.Calls);
        Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
        lock (scans)
        {
            Assert.NotEmpty(scans);
            Assert.All(scans, a =>
            {
                Assert.Equal("True", a.GetTagItem("sentinel.is_clean")?.ToString());
                Assert.Equal("0", a.GetTagItem("sentinel.threat_count")?.ToString());
            });
        }
    }
}
