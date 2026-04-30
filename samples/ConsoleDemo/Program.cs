using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.AI;
using OpenAI;
using System.ClientModel;
using System.Text.Json;
using AI.Sentinel;
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using ZeroAlloc.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: false)
    .AddJsonFile("appsettings.local.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

var apiKey  = config["OpenRouter:ApiKey"]  ?? throw new InvalidOperationException("OpenRouter:ApiKey is required.");
var model   = config["OpenRouter:Model"]   ?? "nvidia/llama-3.3-nemotron-super-49b-v1";
var baseUrl = config["OpenRouter:BaseUrl"] ?? "https://openrouter.ai/api/v1";

static SentinelAction ParseAction(string? value, SentinelAction fallback) =>
    Enum.TryParse<SentinelAction>(value, ignoreCase: true, out var a) ? a : fallback;

var onCritical = ParseAction(config["AISentinel:OnCritical"], SentinelAction.Quarantine);
var onHigh     = ParseAction(config["AISentinel:OnHigh"],     SentinelAction.Alert);
var onMedium   = ParseAction(config["AISentinel:OnMedium"],   SentinelAction.Log);
var onLow      = ParseAction(config["AISentinel:OnLow"],      SentinelAction.Log);

// Build DI container
var services = new ServiceCollection();
services.AddLogging();
services.AddAISentinel(opts =>
{
    opts.OnCritical = onCritical;
    opts.OnHigh     = onHigh;
    opts.OnMedium   = onMedium;
    opts.OnLow      = onLow;
    // To enable semantic (language-agnostic) detection, set an embedding provider:
    // opts.EmbeddingGenerator = new OpenAIEmbeddingGenerator(new OpenAIClient(...), "text-embedding-3-small");

    // Demo: high-stakes tool calls require an out-of-band human approval. The InMemory store
    // is auto-registered when any RequireApproval binding is present. For CLI deployments,
    // swap in AI.Sentinel.Approvals.Sqlite or AI.Sentinel.Approvals.EntraPim — see
    // /docs/approvals/overview.
    opts.RequireApproval("delete_database", spec =>
    {
        spec.GrantDuration = TimeSpan.FromMinutes(15);
        spec.RequireJustification = true;
        spec.BackendBinding = "DBA";
    });
});
services.AddChatClient(svp =>
    new ChatClientBuilder(
        new OpenAIClient(
            new ApiKeyCredential(apiKey),
            new OpenAIClientOptions { Endpoint = new Uri(baseUrl) })
        .GetChatClient(model)
        .AsIChatClient())
    .UseAISentinel()
    .Build(svp));

var sp     = services.BuildServiceProvider();
var client = sp.GetRequiredService<IChatClient>();

Console.WriteLine("AI.Sentinel Console Demo");
Console.WriteLine($"Model  : {model}");
Console.WriteLine($"Actions: Critical={onCritical}, High={onHigh}, Medium={onMedium}, Low={onLow}");
Console.WriteLine("Commands: /approve-demo  walks through the RequireApproval flow end-to-end.");
Console.WriteLine("Type a message and press Enter. Ctrl+C to quit.\n");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true; // prevent immediate process kill
    cts.Cancel();
};

var history = new List<ChatMessage>();

while (!cts.Token.IsCancellationRequested)
{
    Console.Write("You: ");
    var input = Console.ReadLine();
    if (string.IsNullOrWhiteSpace(input)) continue;

    if (string.Equals(input.Trim(), "/approve-demo", StringComparison.OrdinalIgnoreCase))
    {
        await RunApprovalDemoAsync(sp, cts.Token).ConfigureAwait(false);
        continue;
    }

    history.Add(new ChatMessage(ChatRole.User, input));

    Console.Write("AI : ");
    var responseText = new System.Text.StringBuilder();

    try
    {
        await foreach (var update in client.GetStreamingResponseAsync(history, cancellationToken: cts.Token))
        {
            var token = update.Text ?? "";
            responseText.Append(token);
            Console.Write(token);
        }
        Console.WriteLine();
        history.Add(new ChatMessage(ChatRole.Assistant, responseText.ToString()));
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("\nBye!");
        break;
    }
    catch (SentinelException ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        var reason = ex.PipelineResult.Detections.FirstOrDefault()?.Reason ?? "threat detected";
        Console.WriteLine($"\n[BLOCKED by AI.Sentinel: {ex.PipelineResult.MaxSeverity} — {reason}]");
        Console.ResetColor();
        // Remove the blocked user message from history
        history.RemoveAt(history.Count - 1);
    }
}

// /approve-demo: walks through RequireApproval end-to-end without needing the LLM to actually
// invoke a tool. We construct a fake `delete_database` call, send it through IToolCallGuard,
// receive RequireApprovalDecision (with request ID + URL), then auto-approve via IApprovalAdmin
// and re-evaluate the guard — which now returns Allow.
static async Task RunApprovalDemoAsync(IServiceProvider sp, CancellationToken ct)
{
    var guard = sp.GetRequiredService<IToolCallGuard>();
    var store = sp.GetService<IApprovalStore>();
    var admin = store as IApprovalAdmin;
    if (admin is null)
    {
        Console.WriteLine("[demo] No IApprovalAdmin available — this demo needs an in-process store (InMemory or Sqlite).");
        return;
    }

    ISecurityContext caller = new DemoSecurityContext("demo-user");
    var args = JsonSerializer.SerializeToElement(new { tableName = "production_orders" });

    Console.WriteLine("[demo] Invoking guard for tool 'delete_database'...");
    var first = await guard.AuthorizeAsync(caller, "delete_database", args, ct).ConfigureAwait(false);
    if (first is not AuthorizationDecision.RequireApprovalDecision req)
    {
        Console.WriteLine($"[demo] Unexpected — guard returned {first.GetType().Name}. Demo requires a RequireApproval binding for delete_database.");
        return;
    }

    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[demo] RequireApproval — RequestId={req.RequestId}");
    // ApprovalUrl is backend-defined. The InMemory store emits a synthetic 'sentinel://approve/<id>'
    // marker; the dashboard panel (when mounted) is the actual approver UX. Sqlite uses the same
    // marker; EntraPim emits a portal URL.
    Console.WriteLine($"[demo]                   ApprovalUrl={req.ApprovalUrl}  (backend-defined)");
    Console.WriteLine($"[demo]                   WaitTimeout={req.WaitTimeout.TotalSeconds:F0}s");
    Console.ResetColor();

    Console.WriteLine("[demo] Approver acts via IApprovalAdmin.ApproveAsync (this is what the dashboard panel does)...");
    await admin.ApproveAsync(req.RequestId, approverId: "demo-approver", note: "demo run", ct).ConfigureAwait(false);

    Console.WriteLine("[demo] Re-evaluating guard...");
    var second = await guard.AuthorizeAsync(caller, "delete_database", args, ct).ConfigureAwait(false);
    Console.ForegroundColor = second.Allowed ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine($"[demo] Guard now returns: {second.GetType().Name}");
    Console.ResetColor();
    Console.WriteLine();
}

// Minimal ISecurityContext for the demo. Real apps pull this from the auth pipeline.
internal sealed class DemoSecurityContext(string id) : ISecurityContext
{
    public string Id { get; } = id;
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
}
