using ZeroAlloc.Inject;
using System.Runtime.CompilerServices;

[assembly: ZeroAllocInject("AddAISentinelDetectors")]
[assembly: InternalsVisibleTo("AI.Sentinel.Tests")]
[assembly: InternalsVisibleTo("AI.Sentinel.AspNetCore")]
[assembly: InternalsVisibleTo("AI.Sentinel.ClaudeCode")]
[assembly: InternalsVisibleTo("AI.Sentinel.Copilot")]
[assembly: InternalsVisibleTo("AI.Sentinel.Mcp")]
[assembly: InternalsVisibleTo("AI.Sentinel.Sqlite.Tests")]
[assembly: InternalsVisibleTo("AI.Sentinel.Approvals.EntraPim.Tests")]
[assembly: InternalsVisibleTo("AI.Sentinel.ClaudeCode.Cli")]
[assembly: InternalsVisibleTo("AI.Sentinel.Copilot.Cli")]
[assembly: InternalsVisibleTo("AI.Sentinel.Mcp.Cli")]
[assembly: InternalsVisibleTo("AI.Sentinel.Cli")]
[assembly: InternalsVisibleTo("AI.Sentinel.Benchmarks")]

