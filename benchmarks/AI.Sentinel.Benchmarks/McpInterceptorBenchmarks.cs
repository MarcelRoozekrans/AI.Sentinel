using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using AI.Sentinel.Mcp;

namespace AI.Sentinel.Benchmarks;

/// <summary>
/// Microbenchmarks for the per-content-item hot-path of <see cref="ResourceReadInterceptor"/>.
/// </summary>
/// <remarks>
/// <para>
/// A full end-to-end interceptor benchmark would require constructing
/// <c>RequestContext&lt;ReadResourceRequestParams&gt;</c> plus delegate plumbing that depends on
/// SDK internals — deferred to backlog. Instead, we isolate the cheapest-but-most-frequent
/// sub-step: <c>IsAllowedMime</c>, which runs once per <see cref="ModelContextProtocol.Protocol.ResourceContents"/>
/// item in a <c>resources/read</c> response. For a 50-item payload this multiplies by 50.
/// </para>
/// <para>
/// UTF-8 byte-counting + truncation are covered by <see cref="TruncateBenchmarks"/>; the
/// per-item dictionary-allocation for log lines is exercised indirectly by the StderrLogger
/// benchmarks.
/// </para>
/// </remarks>
[Config(typeof(BenchmarkConfig))]
[BenchmarkCategory("Mcp")]
public class McpInterceptorBenchmarks
{
    // Mirrors ResourceReadInterceptor.DefaultMimes — the production allowlist.
    private static readonly HashSet<string> DefaultMimes = new(StringComparer.OrdinalIgnoreCase)
    {
        "text/", "application/json", "application/xml", "application/yaml",
    };

    [Benchmark(Baseline = true, Description = "MIME match — text/plain (prefix hit)")]
    public bool MimeMatch_TextPlainPrefix() =>
        ResourceReadInterceptor.IsAllowedMime("text/plain", DefaultMimes);

    [Benchmark(Description = "MIME match — application/json (exact hit)")]
    public bool MimeMatch_ApplicationJsonExact() =>
        ResourceReadInterceptor.IsAllowedMime("application/json", DefaultMimes);

    [Benchmark(Description = "MIME match — image/png (full miss)")]
    public bool MimeMatch_ImagePngMiss() =>
        ResourceReadInterceptor.IsAllowedMime("image/png", DefaultMimes);

    [Benchmark(Description = "MIME match — null mime (early-out)")]
    public bool MimeMatch_NullMime() =>
        ResourceReadInterceptor.IsAllowedMime(null, DefaultMimes);
}
