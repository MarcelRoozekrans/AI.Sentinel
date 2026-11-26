using AI.Sentinel.Cli;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

[Collection("NonParallel")] // swaps Console.Out and Console.Error
public sealed class ProgramAuditVerifyTests
{
    [Fact]
    public async Task Main_DispatchesAuditVerifyAndReportsAMissingFile()
    {
        var originalError = Console.Error;
        var stderr = new StringWriter();
        Console.SetError(stderr);
        try
        {
            var exit = await Program.Main(["audit-verify", "no-such-export.json", "--organisation", "org-a", "--public-key", Convert.ToBase64String(new byte[32])]);

            Assert.Equal(1, exit);
            Assert.Contains("Could not read", stderr.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Console.SetError(originalError);
        }
    }
}
