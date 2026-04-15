using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.AI;
using OpenAI;
using System.ClientModel;
using AI.Sentinel;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var config = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: false)
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
