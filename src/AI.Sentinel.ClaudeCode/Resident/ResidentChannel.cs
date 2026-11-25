using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Reads and writes the JSON lines of the local channel.</summary>
internal static class ResidentChannel
{
    /// <summary>The longest line either side accepts. A policy input holds a command or a patch, so it can be large.</summary>
    public const int MaxLineBytes = 8 * 1024 * 1024;

    public static async Task WriteAsync<T>(Stream stream, T message, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(message, info);
        var line = new byte[json.Length + 1];
        json.CopyTo(line, 0);
        line[^1] = (byte)'\n';
        await stream.WriteAsync(line, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>The next line, or <see langword="null"/> when the peer closed before one arrived or the line is too long.</summary>
    public static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[4096];
        using var line = new MemoryStream();
        while (true)
        {
            var read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            var newline = Array.IndexOf(buffer, (byte)'\n', 0, read);
            var take = newline < 0 ? read : newline;
            if (line.Length + take > MaxLineBytes)
            {
                return null;
            }

            line.Write(buffer, 0, take);
            if (newline >= 0)
            {
                return Encoding.UTF8.GetString(line.GetBuffer(), 0, (int)line.Length);
            }
        }
    }

    /// <summary>A stream socket of the local channel.</summary>
    public static Socket NewSocket() => new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
}
