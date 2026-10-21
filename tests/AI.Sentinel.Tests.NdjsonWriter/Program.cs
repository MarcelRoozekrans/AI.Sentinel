using System.Globalization;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;

// Usage: AI.Sentinel.Tests.NdjsonWriter <file> <writer-id> <batches> <batch-size> <start-file>
// Prints "ready" once warmed up, then waits until <start-file> exists so every writer process starts
// appending at the same moment, and sends <batches> batches of <batch-size> entries. Entry ids are "<writer>-<batch>-<index>".
// Exit code 0 on success; any send error reported through OnError makes the exit code 1.
if (args.Length != 5)
{
    await Console.Error.WriteLineAsync("usage: <file> <writer-id> <batches> <batch-size> <start-file>");
    return 2;
}

var file = args[0];
var writer = args[1];
var batches = int.Parse(args[2], CultureInfo.InvariantCulture);
var batchSize = int.Parse(args[3], CultureInfo.InvariantCulture);
var startFile = args[4];

var errors = 0;
await using var forwarder = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions
{
    FilePath = file,
    LockTimeout = TimeSpan.FromSeconds(60),
    OnError = message =>
    {
        Interlocked.Increment(ref errors);
        Console.Error.WriteLine(message);
    },
});

// Warm up serialisation and the file-open path on a private file, so the timed part below is all
// contention on the shared one. Then tell the test this writer is ready to be released.
var warmUp = $"{file}.warmup-{writer}";
await using (var warm = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = warmUp }))
{
    await warm.SendAsync([new AuditEntry("warm-up", DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", "warm-up")], CancellationToken.None);
}
File.Delete(warmUp);
File.Delete(warmUp + ".lock");
Console.Out.WriteLine("ready");
await Console.Out.FlushAsync();

var deadline = DateTime.UtcNow.AddSeconds(60);
while (!File.Exists(startFile))
{
    if (DateTime.UtcNow > deadline)
    {
        await Console.Error.WriteLineAsync("start file never appeared");
        return 3;
    }
    await Task.Delay(5);
}

for (var b = 0; b < batches; b++)
{
    var batch = new AuditEntry[batchSize];
    for (var i = 0; i < batchSize; i++)
    {
        batch[i] = new AuditEntry(
            string.Create(CultureInfo.InvariantCulture, $"{writer}-{b}-{i}"),
            DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", new string('x', 512));
    }
    await forwarder.SendAsync(batch, CancellationToken.None);
}

return Volatile.Read(ref errors) == 0 ? 0 : 1;
