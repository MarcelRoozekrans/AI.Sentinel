namespace AI.Sentinel.ServerSample;

// A named entry point, not top-level statements: the test project references the sample and has other programs of its own.
internal static class SampleHost
{
    private static void Main(string[] args) => ServerSampleApp.Build(args).Run();
}
