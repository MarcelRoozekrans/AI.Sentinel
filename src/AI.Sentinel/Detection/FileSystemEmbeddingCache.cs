using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>
/// Persistent <see cref="IEmbeddingCache"/> backed by a single binary file per model.
/// </summary>
/// <remarks>
/// Intended for <see cref="SentinelOptions.ExampleEmbeddingCache"/> in per-invocation hosts. A hook
/// CLI runs one process per prompt and per tool call, so without persistence every invocation
/// re-embeds all of the detectors' example phrases — 82 round-trips for the built-in set. With a warm
/// file the same run costs one call, for the scan input.
/// <para>
/// Do <strong>not</strong> use this for <see cref="SentinelOptions.EmbeddingCache"/>: that cache holds
/// scan-time input, which in a hook is the user's prompt, and an embedding is invertible to
/// approximate source text. Only the static example phrases belong on disk.
/// </para>
/// <para>
/// Entries are keyed by SHA-256 of the text, so no plaintext is written. The model identity selects
/// the file, because <see cref="IEmbeddingCache"/> keys on text alone and vectors from one model are
/// meaningless to another. A file that fails to parse is treated as empty rather than throwing —
/// a cold cache costs latency, a crash costs the scan.
/// </para>
/// </remarks>
public sealed class FileSystemEmbeddingCache : IEmbeddingCache, IDisposable
{
    private const uint Magic = 0x45534941;   // "AISE"
    private const int Version = 1;
    private const int KeyLength = 32;

    private readonly string _path;
    private readonly Dictionary<string, float[]> _entries = new(StringComparer.Ordinal);
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private bool _dirty;
    private bool _disposed;

    /// <param name="directory">Directory to hold the cache file. Created if missing.</param>
    /// <param name="modelId">Identity of the embedding model whose vectors this file holds.</param>
    public FileSystemEmbeddingCache(string directory, string modelId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);

        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, $"examples-{Fingerprint(modelId)}.bin");
        Load();
    }

    /// <inheritdoc />
    public bool TryGet(string text, out Embedding<float> embedding)
    {
        ArgumentNullException.ThrowIfNull(text);
        lock (_lock)
        {
            if (_entries.TryGetValue(KeyOf(text), out var vector))
            {
                embedding = new Embedding<float>(vector);
                return true;
            }
        }

        embedding = default!;
        return false;
    }

    /// <inheritdoc />
    public void Set(string text, Embedding<float> embedding)
    {
        ArgumentNullException.ThrowIfNull(text);
        lock (_lock)
        {
            _entries[KeyOf(text)] = embedding.Vector.ToArray();
            _dirty = true;
        }
    }

    /// <summary>Writes pending entries to disk. Called automatically on dispose.</summary>
    public void Flush()
    {
        lock (_lock)
        {
            if (!_dirty) return;

            try
            {
                // Temp-and-rename: concurrent hook processes race, and a half-written file read by
                // another process must never be possible. Content is deterministic per (model, text),
                // so a last-writer-wins outcome converges.
                var temp = $"{_path}.{Environment.ProcessId}.tmp";
                using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    Write(stream);
                }

                File.Move(temp, _path, overwrite: true);
                _dirty = false;
            }
            catch (IOException)
            {
                // A cache that cannot persist is still a working in-memory cache.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void Write(Stream stream)
    {
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(header[..4], Magic);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(4, 4), Version);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(8, 4), _entries.Count);
        stream.Write(header);

        Span<byte> intBuffer = stackalloc byte[4];
        foreach (var (key, vector) in _entries)
        {
            stream.Write(Convert.FromHexString(key));
            BinaryPrimitives.WriteInt32LittleEndian(intBuffer, vector.Length);
            stream.Write(intBuffer);
            // Bulk copy — the file is a machine-local cache, so native float layout is fine.
            stream.Write(MemoryMarshal.AsBytes(vector.AsSpan()));
        }
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;

        try
        {
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> header = stackalloc byte[12];
            if (stream.ReadAtLeast(header, 12, throwOnEndOfStream: false) < 12) return;
            if (BinaryPrimitives.ReadUInt32LittleEndian(header[..4]) != Magic) return;
            if (BinaryPrimitives.ReadInt32LittleEndian(header.Slice(4, 4)) != Version) return;

            var count = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(8, 4));
            if (count < 0) return;

            var staged = new Dictionary<string, float[]>(StringComparer.Ordinal);
            Span<byte> key = stackalloc byte[KeyLength];
            Span<byte> intBuffer = stackalloc byte[4];

            for (var i = 0; i < count; i++)
            {
                if (stream.ReadAtLeast(key, KeyLength, throwOnEndOfStream: false) < KeyLength) return;
                if (stream.ReadAtLeast(intBuffer, 4, throwOnEndOfStream: false) < 4) return;

                var length = BinaryPrimitives.ReadInt32LittleEndian(intBuffer);
                if (length is < 0 or > 1 << 16) return;

                var vector = new float[length];
                var destination = MemoryMarshal.AsBytes(vector.AsSpan());
                if (stream.ReadAtLeast(destination, destination.Length, throwOnEndOfStream: false) < destination.Length) return;

                staged[Convert.ToHexString(key)] = vector;
            }

            // Only adopt a file that parsed end to end — a truncated file yields a cold cache.
            foreach (var (k, v) in staged) _entries[k] = v;
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string KeyOf(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string Fingerprint(string modelId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(modelId)))[..16];

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Flush();
    }
}
