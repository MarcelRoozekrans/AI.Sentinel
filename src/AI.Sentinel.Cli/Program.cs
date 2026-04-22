using System.CommandLine;

namespace AI.Sentinel.Cli;

public static class Program
{
    public static Task<int> Main(string[] args)
    {
        var root = new RootCommand("AI.Sentinel - offline replay CLI")
        {
            ScanCommand.Build(),
        };
        return root.Parse(args).InvokeAsync();
    }
}
