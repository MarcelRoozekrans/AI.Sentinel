using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.AI;
using AI.Sentinel.Intervention;
using ChatApp.Shared;

namespace ChatApp.Server.Hubs;

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

        // Use CancellationToken.None as the Task.Run scheduler token so that a pre-cancelled
        // token does not prevent the lambda from starting — the channel would otherwise never be
        // completed and ReadAllAsync would hang indefinitely.
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
            }
            catch (SentinelException ex)
            {
                var reason = ex.PipelineResult.Detections.FirstOrDefault()?.Reason ?? "threat detected";
                channel.Writer.TryWrite($"\0BLOCKED:{reason}");
            }
            catch (OperationCanceledException)
            {
                // Client disconnected — channel completes normally via finally
            }
            catch (Exception)
            {
                channel.Writer.TryWrite("\0ERROR");
            }
            finally
            {
                channel.Writer.TryComplete();
            }
        }, CancellationToken.None);

        await foreach (var token in channel.Reader.ReadAllAsync(cancellationToken))
            yield return token;
    }
}
