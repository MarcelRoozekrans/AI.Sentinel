using System.Text;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Reads Server-Sent Events from a stream. Written by hand, with no reflection, so it is safe under Native AOT. A stream that says
/// nothing, not even a heartbeat, for <c>stall</c> is dead, and the read fails so the caller reconnects.
/// </summary>
internal static class SseReader
{
    /// <summary>The most data one event may carry; a server that sends more is not one of ours.</summary>
    public const int MaxEventBytes = 1 << 20;

    public static async IAsyncEnumerable<SseMessage> ReadAsync(
        Stream stream, TimeSpan stall, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        string? name = null;
        var data = new StringBuilder();
        var hasData = false;
        while (true)
        {
            var line = await ReadLineAsync(reader, stall, ct).ConfigureAwait(false);
            if (line is null)
            {
                yield break;
            }

            if (line.Length == 0)
            {
                if (hasData || name is not null)
                {
                    yield return new SseMessage(name, hasData ? data.ToString() : string.Empty);
                }

                name = null;
                data.Clear();
                hasData = false;
                continue;
            }

            if (line[0] == ':')
            {
                yield return new SseMessage(null, null);
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            var field = colon < 0 ? line : line[..colon];
            var value = colon < 0 ? string.Empty : line[(colon + 1)..];
            if (value.StartsWith(' '))
            {
                value = value[1..];
            }

            if (string.Equals(field, "event", StringComparison.Ordinal))
            {
                name = value;
            }
            else if (string.Equals(field, "data", StringComparison.Ordinal))
            {
                if (data.Length + value.Length > MaxEventBytes)
                {
                    throw new InvalidDataException("an event is larger than the limit");
                }

                if (hasData)
                {
                    data.Append('\n');
                }

                data.Append(value);
                hasData = true;
            }
        }
    }

    private static async Task<string?> ReadLineAsync(StreamReader reader, TimeSpan stall, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(stall);
        try
        {
            return await reader.ReadLineAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException e) when (!ct.IsCancellationRequested)
        {
            throw new IOException("the event stream went quiet", e);
        }
    }
}
