using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;

namespace AI.Sentinel.Benchmarks;

internal sealed class BenchmarkConfig : ManualConfig
{
    public BenchmarkConfig()
    {
        AddJob(Job.Default.WithId("Default"));
        AddDiagnoser(MemoryDiagnoser.Default);
        AddDiagnoser(ThreadingDiagnoser.Default);
        AddExporter(MarkdownExporter.GitHub);
        AddColumn(StatisticColumn.P95);
    }
}
