using System.Net;
using System.Net.Sockets;
using AI.Sentinel.Alerts;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Alerts;

public class AlertSinkTests
{
    /// <summary>
    /// Reserves an ephemeral port via TcpListener:0, then releases it so HttpListener can rebind.
    /// Eliminates the fixed-port collisions that flaked CI builds — Windows agents reuse ports
    /// quickly and fixed numbers (19998 etc.) can clash with other concurrent test work.
    /// </summary>
    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try { return ((IPEndPoint)l.LocalEndpoint).Port; }
        finally { l.Stop(); }
    }

    [Fact]
    public async Task NullAlertSink_DoesNotThrow()
    {
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Quarantine,
            SessionId.New());
        await NullAlertSink.Instance.SendAsync(error, default);
        // reaching here confirms no throw
    }

    [Fact]
    public async Task NullAlertSink_PipelineFailure_DoesNotThrow()
    {
        var error = new SentinelError.PipelineFailure("network error");
        await NullAlertSink.Instance.SendAsync(error, default);
    }

    [Fact]
    public async Task WebhookAlertSink_UnreachableEndpoint_DoesNotThrow()
    {
        // Endpoint is deliberately unreachable — webhook failures must never surface to caller.
        var sink = new WebhookAlertSink(new Uri("http://localhost:19999/nonexistent"));
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Alert,
            SessionId.New());
        await sink.SendAsync(error, default);
        // reaching here confirms the exception was swallowed
    }

    [Fact]
    public async Task WebhookAlertSink_ThreatDetected_PostsCorrectJsonPayload()
    {
        var port = GetFreePort();
        using var listener = new System.Net.HttpListener();
        listener.Prefixes.Add($"http://localhost:{port}/hook/");
        listener.Start();

        string capturedBody = "";
        var serverTask = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            using var reader = new StreamReader(ctx.Request.InputStream);
            capturedBody = await reader.ReadToEndAsync();
            ctx.Response.StatusCode = 200;
            ctx.Response.Close();
        });

        var sink = new WebhookAlertSink(new Uri($"http://localhost:{port}/hook/"));
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-99"), Severity.High, "test reason"),
            SentinelAction.Alert,
            SessionId.New());

        await sink.SendAsync(error, default);
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        listener.Stop();

        Assert.Contains("\"type\":\"ThreatDetected\"", capturedBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SEC-99", capturedBody, StringComparison.Ordinal);
        Assert.Contains("High", capturedBody, StringComparison.Ordinal);
        Assert.Contains("test reason", capturedBody, StringComparison.Ordinal);
        Assert.Contains("Alert", capturedBody, StringComparison.Ordinal);
        Assert.Contains("\"session\":", capturedBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WebhookAlertSink_PipelineFailure_PostsCorrectJsonPayload()
    {
        var port = GetFreePort();
        using var listener = new System.Net.HttpListener();
        listener.Prefixes.Add($"http://localhost:{port}/hook/");
        listener.Start();

        string capturedBody = "";
        var serverTask = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            using var reader = new StreamReader(ctx.Request.InputStream);
            capturedBody = await reader.ReadToEndAsync();
            ctx.Response.StatusCode = 200;
            ctx.Response.Close();
        });

        var sink = new WebhookAlertSink(new Uri($"http://localhost:{port}/hook/"));
        var error = new SentinelError.PipelineFailure("something failed");

        await sink.SendAsync(error, default);
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        listener.Stop();

        Assert.Contains("\"type\":\"PipelineFailure\"", capturedBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("something failed", capturedBody, StringComparison.Ordinal);
    }
}
