using System.Text.Json.Serialization.Metadata;

namespace AI.Sentinel.Http;

/// <summary>
/// Shared behaviour of the OpenAI-compatible HTTP clients: what an error message may show of an
/// endpoint, and how much of a response is read.
/// </summary>
/// <remarks>
/// Endpoint URLs and provider error bodies routinely carry secrets: <c>?api-key=</c> query strings,
/// <c>user:pass@</c> userinfo, and masked keys echoed back in a 401 body. Messages end up in logs and
/// hook output, so none of that may be quoted.
/// </remarks>
internal static class SafeHttp
{
    /// <summary>Scheme, host, port and path only: no userinfo, no query, no fragment.</summary>
    internal static string Describe(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var port = endpoint.IsDefaultPort ? string.Empty : $":{endpoint.Port}";
        return $"{endpoint.Scheme}://{endpoint.Host}{port}{endpoint.AbsolutePath}";
    }

    /// <summary>
    /// Scheme, host and port only: no userinfo, path, query or fragment. For a webhook the path is the credential
    /// (Slack, Discord, Teams, an ntfy topic), so a log line names the origin and nothing more.
    /// </summary>
    internal static string DescribeOrigin(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var port = endpoint.IsDefaultPort ? string.Empty : $":{endpoint.Port}";
        return $"{endpoint.Scheme}://{endpoint.Host}{port}";
    }

    /// <summary>The endpoint with userinfo, query and fragment removed.</summary>
    internal static Uri Redact(Uri endpoint) => new(Describe(endpoint), UriKind.Absolute);

    /// <summary>
    /// Deserialises the response body, reading at most <paramref name="limit"/> bytes. The limit is
    /// enforced on the stream, so it holds for a caller-supplied <see cref="HttpClient"/> as well; the
    /// request must be sent with <see cref="HttpCompletionOption.ResponseHeadersRead"/> for the body to
    /// not be buffered first.
    /// </summary>
    /// <exception cref="InvalidDataException">The body exceeds <paramref name="limit"/> or is not the expected JSON.</exception>
    internal static async Task<T?> ReadJsonAsync<T>(
        HttpContent content, JsonTypeInfo<T> typeInfo, int limit, string what, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is { } declared && declared > limit)
        {
            throw TooLarge(what, limit);
        }

        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > limit) throw TooLarge(what, limit);
            buffer.Write(chunk, 0, read);
        }

        buffer.Position = 0;
        try
        {
            return await System.Text.Json.JsonSerializer
                .DeserializeAsync(buffer, typeInfo, cancellationToken).ConfigureAwait(false);
        }
        catch (System.Text.Json.JsonException ex)
        {
            // Wrong shape, such as an array where a string is expected, is bad data like a missing field.
            throw new InvalidDataException($"{what} response is not the expected JSON shape.", ex);
        }
    }

    /// <summary>Parses an absolute http or https URL.</summary>
    internal static bool TryParseHttpEndpoint(string value, out Uri endpoint)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            && (parsed.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.Ordinal)
                || parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            endpoint = parsed;
            return true;
        }

        endpoint = null!;
        return false;
    }

    private static InvalidDataException TooLarge(string what, int limit) =>
        new($"{what} response exceeds the {limit} byte limit.");
}
