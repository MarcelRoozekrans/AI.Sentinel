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

    /// <summary>The longest line of any kind, checked while it is read, so a server that never ends a line cannot grow memory.</summary>
    public const int MaxLineChars = MaxEventBytes;

    public static async IAsyncEnumerable<SseMessage> ReadAsync(
        Stream stream, TimeSpan stall, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        var lines = new LineReader(reader);
        string? name = null;
        var data = new StringBuilder();
        var hasData = false;
        while (true)
        {
            var line = await ReadLineAsync(lines, stall, ct).ConfigureAwait(false);
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
                AppendData(data, hasData, value);
                hasData = true;
            }
        }
    }

    private static void AppendData(StringBuilder data, bool hasData, string value)
    {
        if (data.Length + value.Length > MaxEventBytes)
        {
            throw new InvalidDataException("an event is larger than the limit");
        }

        if (hasData)
        {
            _ = data.Append('\n');
        }

        _ = data.Append(value);
    }

    private static async Task<string?> ReadLineAsync(LineReader lines, TimeSpan stall, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(stall);
        try
        {
            return await lines.ReadLineAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException e) when (!ct.IsCancellationRequested)
        {
            throw new IOException("the event stream went quiet", e);
        }
    }

    // Reads lines in chunks and fails a line as soon as it passes MaxLineChars, before it is allocated as a string.
    private sealed class LineReader(StreamReader reader)
    {
        private readonly char[] _buffer = new char[4096];
        private readonly StringBuilder _line = new();
        private int _pos;
        private int _len;
        private bool _skipLf;

        // Moves the unread chars up to a line end into the line; returns 1 at a line end and -1 when the chunk is used up.
        private int Take()
        {
            var span = _buffer.AsSpan(_pos, _len - _pos);
            var end = span.IndexOfAny('\r', '\n');
            var take = end < 0 ? span.Length : end;
            if (_line.Length + take > MaxLineChars)
            {
                throw new InvalidDataException("a line is longer than the limit");
            }

            _ = _line.Append(span[..take]);
            if (end < 0)
            {
                _pos = _len;
                return -1;
            }

            _skipLf = span[end] == '\r';
            _pos += end + 1;
            return 1;
        }

        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            _line.Clear();
            while (true)
            {
                if (_pos == _len)
                {
                    _len = await reader.ReadAsync(_buffer.AsMemory(), ct).ConfigureAwait(false);
                    _pos = 0;
                    if (_len == 0)
                    {
                        return _line.Length > 0 ? _line.ToString() : null;
                    }
                }

                if (_skipLf)
                {
                    _skipLf = false;
                    if (_buffer[_pos] == '\n')
                    {
                        _pos++;
                        continue;
                    }
                }

                var end = Take();
                if (end < 0)
                {
                    continue;
                }

                return _line.ToString();
            }
        }
    }
}
