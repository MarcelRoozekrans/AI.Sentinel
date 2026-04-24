namespace AI.Sentinel.Mcp.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
        => await RunAsync(args, Console.In, Console.Out, Console.Error).ConfigureAwait(false);

    public static async Task<int> RunAsync(
        string[] args, TextReader stdin, TextWriter stdout, TextWriter stderr)
    {
        if (args.Length < 1 || !string.Equals(args[0], "proxy", StringComparison.Ordinal))
        {
            await stderr.WriteLineAsync("Usage: sentinel-mcp proxy --target <command> [<target-args>...]").ConfigureAwait(false);
            return 1;
        }

        // Proxy execution lands in Task 10.
        await stderr.WriteLineAsync("proxy subcommand not yet implemented").ConfigureAwait(false);
        return 1;
    }
}
