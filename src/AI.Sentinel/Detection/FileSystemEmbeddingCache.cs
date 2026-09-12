using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>
/// Persistent <see cref="IEmbeddingCache"/> backed by a single binary file per model and dimension.
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
/// <para><strong>Integrity.</strong> The file is not authenticated. Anyone who can write to the cache
/// directory can replace the reference vectors with noise, which would push every bucket below
/// threshold and silently disable semantic detection. Point this at a directory only the running user
/// can write — a world-writable temp path is not a safe location.
/// </para>
/// <para>
/// Entries are keyed by SHA-256 of the text, so no plaintext is written. Model identity and vector
/// dimension both select the file: <see cref="IEmbeddingCache"/> keys on text alone, and serving a
/// vector of the wrong dimension would make cosine similarity score 0 for every comparison — a silent
/// detection bypass rather than a visible failure.
/// </para>
/// <para>
/// A flush takes one exclusive handle and does the read, merge and rewrite through it, so concurrent
/// writers converge on the union instead of overwriting one another; a collision is retried briefly
/// and then abandoned, because the cache is advisory and a miss only costs re-embedding. Readers share
/// the file with writers, and every read validates the header and entry lengths, so a torn or
/// truncated file is treated as empty. A cold cache costs latency; a corrupt one would cost the scan.
/// </para>
/// </remarks>
public sealed class FileSystemEmbeddingCache : IEmbeddingCache, IDisposable
{
    private const uint Magic = 0x45534941;   // "AISE"
    private const int Version = 2;
    private const int KeyLength = 32;
    private const int HeaderLength = 16;
    private const int MaxDimensions = 1 << 16;

    /// <summary>Entries buffered before an automatic flush. Persisting only on dispose meant the
    /// obvious inline usage — assigning the cache to an option nothing ever disposes — wrote nothing,
    /// leaving the cache permanently cold and the feature apparently inert.</summary>
    private const int AutoFlushThreshold = 64;

    private const int WriteAttempts = 8;
    private const int WriteRetryDelayMs = 5;

    private readonly string _path;
    private readonly int _dimensions;
    private readonly Dictionary<string, float[]> _entries = new(StringComparer.Ordinal);
#if NET9_0_OR_GREATER
    private readonly System.Threading.Lock _lock = new();
#else
    private readonly object _lock = new();
#endif
    private int _pendingWrites;
    private bool _dirty;
    private bool _disposed;

    /// <param name="directory">Directory to hold the cache file. Created if missing. Must not be
    /// writable by anyone but the running user — see the integrity note on this type.</param>
    /// <param name="modelId">Identity of the embedding model whose vectors this file holds.</param>
    /// <param name="dimensions">Vector length the generator produces, when known. Supply it whenever
    /// available: cosine similarity scores a length mismatch as 0, so vectors from another dimension
    /// would make every semantic detector return Clean without raising anything.</param>
    public FileSystemEmbeddingCache(string directory, string modelId, int? dimensions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        if (dimensions is <= 0 or > MaxDimensions)
        {
            throw new ArgumentOutOfRangeException(nameof(dimensions));
        }

        _dimensions = dimensions ?? 0;
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, $"examples-{Fingerprint(modelId, _dimensions)}.bin");

        if (TryReadFile(out var stored))
        {
            foreach (var (key, vector) in stored) _entries[key] = vector;
        }
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

        bool flushNow;
        lock (_lock)
        {
            _entries[KeyOf(text)] = embedding.Vector.ToArray();
            _dirty = true;
            _pendingWrites++;
            flushNow = _pendingWrites >= AutoFlushThreshold;
        }

        if (flushNow) Flush();
    }

    /// <summary>Merges what is on disk and rewrites the file. Called automatically once enough entries
    /// have accumulated, and on dispose.</summary>
    public void Flush()
    {
        lock (_lock)
        {
            if (!_dirty) return;

            for (var attempt = 0; attempt < WriteAttempts; attempt++)
            {
                if (TryMergeAndWrite()) return;
                Thread.Sleep(WriteRetryDelayMs);
            }
        }
    }

    /// <summary>One exclusive handle spanning read, merge and rewrite. Reading the file and then
    /// reopening it to write leaves a window in which another writer lands and this process clobbers
    /// it — a silent lost update that no retry can detect.</summary>
    private bool TryMergeAndWrite()
    {
        try
        {
            using var stream = new FileStream(
                _path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

            if (TryReadFrom(stream, out var stored))
            {
                foreach (var (key, vector) in stored)
                {
                    if (!_entries.ContainsKey(key)) _entries[key] = vector;
                }
            }

            stream.Position = 0;
            stream.SetLength(0);
            Write(stream);

            _dirty = false;
            _pendingWrites = 0;
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void Write(Stream stream)
    {
        Span<byte> header = stackalloc byte[HeaderLength];
        BinaryPrimitives.WriteUInt32LittleEndian(header[..4], Magic);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(4, 4), Version);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(8, 4), _dimensions);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(12, 4), _entries.Count);
        stream.Write(header);

        Span<byte> lengthBuffer = stackalloc byte[4];
        foreach (var (key, vector) in _entries)
        {
            stream.Write(Convert.FromHexString(key));
            BinaryPrimitives.WriteInt32LittleEndian(lengthBuffer, vector.Length);
            stream.Write(lengthBuffer);
            // Bulk copy — the file is a machine-local cache, so native float layout is fine.
            stream.Write(MemoryMarshal.AsBytes(vector.AsSpan()));
        }
    }

    private bool TryReadFile(out Dictionary<string, float[]> entries)
    {
        entries = new Dictionary<string, float[]>(StringComparer.Ordinal);
        if (!File.Exists(_path)) return false;

        try
        {
            // ReadWrite share: a reader that locked out writers would cost a concurrent hook its whole
            // flush. A torn read is caught by the validation in TryReadFrom.
            using var stream = new FileStream(
                _path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return TryReadFrom(stream, out entries);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Parses the stream, reporting failure for anything that does not read end to end.</summary>
    private bool TryReadFrom(Stream stream, out Dictionary<string, float[]> entries)
    {
        entries = new Dictionary<string, float[]>(StringComparer.Ordinal);
        stream.Position = 0;

        Span<byte> header = stackalloc byte[HeaderLength];
        if (stream.ReadAtLeast(header, HeaderLength, throwOnEndOfStream: false) < HeaderLength) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(header[..4]) != Magic) return false;
        if (BinaryPrimitives.ReadInt32LittleEndian(header.Slice(4, 4)) != Version) return false;

        var fileDimensions = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(8, 4));
        if (_dimensions != 0 && fileDimensions != 0 && fileDimensions != _dimensions) return false;

        var count = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(12, 4));
        if (count < 0) return false;

        if (!TryReadEntries(stream, count, fileDimensions, out var staged)) return false;

        entries = staged;
        return true;
    }

    private bool TryReadEntries(Stream stream, int count, int fileDimensions, out Dictionary<string, float[]> staged)
    {
        staged = new Dictionary<string, float[]>(StringComparer.Ordinal);
        Span<byte> key = stackalloc byte[KeyLength];
        Span<byte> lengthBuffer = stackalloc byte[4];

        for (var i = 0; i < count; i++)
        {
            if (stream.ReadAtLeast(key, KeyLength, throwOnEndOfStream: false) < KeyLength) return false;
            if (stream.ReadAtLeast(lengthBuffer, 4, throwOnEndOfStream: false) < 4) return false;

            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
            if (length is <= 0 or > MaxDimensions) return false;
            if (fileDimensions != 0 && length != fileDimensions) return false;
            if (_dimensions != 0 && length != _dimensions) return false;

            var vector = new float[length];
            var destination = MemoryMarshal.AsBytes(vector.AsSpan());
            if (stream.ReadAtLeast(destination, destination.Length, throwOnEndOfStream: false) < destination.Length)
            {
                return false;
            }

            staged[Convert.ToHexString(key)] = vector;
        }

        return true;
    }

    private static string KeyOf(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string Fingerprint(string modelId, int dimensions)
    {
        var seed = $"{modelId}|{dimensions.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed)))[..16];
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
        }

        Flush();
    }
}
