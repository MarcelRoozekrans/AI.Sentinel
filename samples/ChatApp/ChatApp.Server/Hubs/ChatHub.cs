using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.AI;
using AI.Sentinel.Intervention;

namespace ChatApp.Server.Hubs;

/// <summary>Simple message DTO shared between client and server over SignalR.</summary>
/// <param name="Role">"user" or "assistant"</param>
/// <param name="Text">Message text</param>
public record ChatMessageDto(string Role, string Text);

public sealed class ChatHub(IChatClient chatClient) : Hub
{
    public async IAsyncEnumerable<string> StreamResponse(
        string userMessage,
        IEnumerable<ChatMessageDto> history,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messages = history
            .Select(m => new ChatMessage(
                m.Role == "user" ? ChatRole.User : ChatRole.Assistant,
                m.Text))
            .Append(new ChatMessage(ChatRole.User, userMessage))
            .ToList();

        var stream = chatClient.GetStreamingResponseAsync(messages, cancellationToken: cancellationToken);

        // Collect tokens via an async channel so we can translate exceptions to sentinel strings
        // without needing yield-in-catch (not allowed in C#).
        var channel = System.Threading.Channels.Channel.CreateUnbounded<string>();

        _ = Task.Run(async () =>
        {
            try
            {
                await foreach (var update in stream.WithCancellation(cancellationToken))
                {
                    var text = update.Text;
                    if (!string.IsNullOrEmpty(text))
                        channel.Writer.TryWrite(text);
                }
                channel.Writer.Complete();
            }
            catch (SentinelException ex)
            {
                var reason = ex.PipelineResult.Detections.FirstOrDefault()?.Reason ?? "threat detected";
                channel.Writer.TryWrite($"\0BLOCKED:{reason}");
                channel.Writer.Complete();
            }
            catch (OperationCanceledException)
            {
                channel.Writer.Complete();
            }
            catch (Exception)
            {
                channel.Writer.TryWrite("\0ERROR");
                channel.Writer.Complete();
            }
        }, cancellationToken);

        await foreach (var token in channel.Reader.ReadAllAsync(cancellationToken))
            yield return token;
    }
}
