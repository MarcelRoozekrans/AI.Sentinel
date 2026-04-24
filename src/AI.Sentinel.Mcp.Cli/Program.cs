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
            await stderr.WriteLineAsync(
                "Usage: sentinel-mcp proxy --target <command> [<target-args>...]"
            ).ConfigureAwait(false);
            return 1;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            return await ProxyCommand.RunAsync(args, stdin, stdout, stderr, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync(
                $"sentinel-mcp: internal error: {ex.GetType().Name}: {ex.Message}"
            ).ConfigureAwait(false);
            return 1;
        }
    }
}
