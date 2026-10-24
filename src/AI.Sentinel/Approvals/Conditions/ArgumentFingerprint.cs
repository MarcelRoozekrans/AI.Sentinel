using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.Approvals.Conditions;

/// <summary>
/// Fingerprints tool arguments for call-scoped grants. Two argument sets that differ only in
/// object key order, insignificant whitespace or string escaping get the same fingerprint.
/// </summary>
internal static class ArgumentFingerprint
{
    private const int FingerprintBytes = 16;

    /// <summary>
    /// Returns the first 32 lowercase hex characters, 128 bits, of the SHA-256 of the UTF-8 byte
    /// length of the tool name as 4 bytes big-endian, the UTF-8 tool name and the canonical arguments: object keys sorted ordinally, no
    /// insignificant whitespace, strings re-escaped by the default <see cref="Utf8JsonWriter"/>
    /// encoder, numbers as their raw token. The tool name is part of the hash so a grant for one
    /// tool never covers another tool that a wildcard rule also matches.
    /// Arguments of kind <see cref="JsonValueKind.Undefined"/> hash as empty input. Arguments
    /// holding a string or property name that does not decode to valid UTF-16, such as a lone
    /// surrogate escape, hash their raw JSON text behind a marker byte instead. Never throws on any arguments.
    /// </summary>
    public static string Compute(string toolName, JsonElement args)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        // Length-prefixed, so no tool name can run into the arguments or their raw-fallback marker byte.
        var name = Encoding.UTF8.GetBytes(toolName);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, name.Length);
        sha.AppendData(length);
        sha.AppendData(name);
        sha.AppendData(Canonicalize(args));
        Span<byte> hash = stackalloc byte[32];
        sha.GetHashAndReset(hash);
        return ToLowerHex(hash[..FingerprintBytes]);
    }

    private static byte[] Canonicalize(JsonElement args)
    {
        if (args.ValueKind == JsonValueKind.Undefined)
            return [];

        var buffer = new ArrayBufferWriter<byte>();
        try
        {
            using (var writer = new Utf8JsonWriter(buffer))
                WriteCanonical(writer, args);
            return buffer.WrittenSpan.ToArray();
        }
        catch (InvalidOperationException)
        {
            // System.Text.Json has no non-throwing decode for invalid UTF-16 escapes. Fall back to
            // the raw text; the 0x00 marker can never start canonical JSON, so the two forms never collide.
            var raw = Encoding.UTF8.GetBytes(args.GetRawText());
            var bytes = new byte[raw.Length + 1];
            raw.CopyTo(bytes, 1);
            return bytes;
        }
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                // OrderBy is stable: duplicate keys keep their relative order, so a tool that
                // reads the last duplicate cannot be handed a different value under the same grant.
                foreach (var property in element.EnumerateObject().OrderBy(static p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                    WriteCanonical(writer, item);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText(), skipInputValidation: true);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            default:
                writer.WriteNullValue();
                break;
        }
    }

    private static string ToLowerHex(ReadOnlySpan<byte> bytes)
    {
        const string digits = "0123456789abcdef";
        Span<char> chars = stackalloc char[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = digits[bytes[i] >> 4];
            chars[(i * 2) + 1] = digits[bytes[i] & 0xF];
        }
        return new string(chars);
    }
}
