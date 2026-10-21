using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Xunit;

namespace AI.Sentinel.Tests.Aot;

/// <summary>Publishes tests/AI.Sentinel.Aot.Probe with Native AOT and reads ILC's warnings.
/// <c>AddDetector&lt;T&gt;</c> stores <c>typeof(T)</c> in <c>SentinelOptions.DetectorRegistration</c>, whose
/// <c>DetectorType</c> property carries <c>PublicConstructors</c>; without the same annotation on the
/// constructor parameter, ILC reports IL2069 at the record's constructor. The factory overload of
/// <c>AddDetector&lt;T&gt;</c> has an unannotated <c>T</c>, so if it passed <c>typeof(T)</c> as the detector type,
/// ILC would report IL2087 at that call; the probe roots both overloads.</summary>
public partial class DetectorRegistrationTrimTests
{
    private const string ProbeProject = "AI.Sentinel.Aot.Probe";

    [Fact]
    public async Task Publishing_the_probe_reports_no_trim_warning_for_detector_registration()
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.OSArchitecture != Architecture.X64)
        {
            Assert.Skip("The probe publishes for linux-x64 only.");
        }

        if (FindOnPath("clang") is null)
        {
            Assert.Skip("clang is not on PATH, so Native AOT cannot link here. Install clang and zlib1g-dev.");
        }

        // The test project builds for net8.0 and net10.0, and both legs may run on the .NET 10 runtime. The
        // publish does not depend on the leg, so only the net10.0 build runs it.
#if !NET10_0_OR_GREATER
        Assert.Skip("The probe publish runs once, from the net10.0 build of this test project.");
#endif

        var temp = Directory.CreateTempSubdirectory("ai-sentinel-aot-probe-").FullName;
        try
        {
            var (exitCode, output) = await PublishAsync(temp);
            var ilLines = output
                .Split('\n')
                .Select(line => line.TrimEnd('\r'))
                .Where(line => IlWarning().IsMatch(line))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            // Other trim and AOT warnings are allowed on 2.x, which does not set IsAotCompatible; print them.
            var log = TestContext.Current.TestOutputHelper;
            log?.WriteLine($"Probe publish exit code {exitCode}; {ilLines.Count} distinct IL warning line(s):");
            foreach (var line in ilLines)
            {
                log?.WriteLine(line);
            }

            // Red: break the probe's Program.cs so it does not compile: the publish exits 1, and a failed
            // publish never counts as zero warnings.
            Assert.True(exitCode == 0, $"The probe publish failed with exit code {exitCode}:\n{Tail(output)}");

            // Red: drop DynamicallyAccessedMembers from the detectorType parameter of DetectorRegistration's
            // constructor: ILC reports IL2069 at SentinelOptions.DetectorRegistration..ctor.
            var il2069 = ilLines
                .Where(line => line.Contains("IL2069", StringComparison.Ordinal)
                    && line.Contains("DetectorRegistration", StringComparison.Ordinal))
                .ToList();
            Assert.True(il2069.Count == 0, "ILC reported IL2069 for DetectorRegistration:\n" + string.Join('\n', il2069));

            // Red: let the factory overload of AddDetector<T> pass typeof(T) as DetectorType again: its T has
            // no annotation, so ILC reports IL2087 at that call once the probe roots the factory overload.
            var il2087 = ilLines
                .Where(line => line.Contains("IL2087", StringComparison.Ordinal)
                    && line.Contains("SentinelOptionsDetectorExtensions", StringComparison.Ordinal))
                .ToList();
            Assert.True(il2087.Count == 0, "ILC reported IL2087 for AddDetector<T>:\n" + string.Join('\n', il2087));
        }
        finally
        {
            DeleteQuietly(temp);
        }
    }

    /// <summary>Publishes into a fresh <c>--artifacts-path</c>: an up-to-date publish prints no warnings and would
    /// pass for the wrong reason. <c>TrimmerSingleWarn=false</c> keeps ILC from folding AI.Sentinel's warnings
    /// into one IL2104 line, since AI.Sentinel 2.x is not marked trimmable.</summary>
    private static async Task<(int ExitCode, string Output)> PublishAsync(string temp)
    {
        var root = RepoRoot();
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in (string[])[
            "publish", Path.Combine(root, "tests", ProbeProject, ProbeProject + ".csproj"),
            "-c", "Release", "-r", "linux-x64",
            "-p:PublishAot=true", "-p:TreatWarningsAsErrors=false", "-p:TrimmerSingleWarn=false",
            "--artifacts-path", Path.Combine(temp, "artifacts"), "-o", Path.Combine(temp, "publish"),
            "-tl:off", "--disable-build-servers"])
        {
            start.ArgumentList.Add(argument);
        }

        // The test runner's own MSBuild settings must not leak into the child build.
        var inherited = start.Environment.Keys
            .Where(k => k.StartsWith("MSBuild", StringComparison.OrdinalIgnoreCase))
            .ToList();
        foreach (var name in inherited)
        {
            start.Environment.Remove(name);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not start dotnet publish.");
        var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(20));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            // A timed-out or cancelled publish must not outlive the test, with ILC still running under it.
            process.Kill(entireProcessTree: true);
            throw;
        }

        return (process.ExitCode, await stdout + await stderr);
    }

    private static string Tail(string output) => output.Length > 6000 ? output[^6000..] : output;

    private static string? FindOnPath(string command) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, command))
            .FirstOrDefault(File.Exists);

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "AI.Sentinel.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new InvalidOperationException("AI.Sentinel.slnx not found above the test output.");
    }

    private static void DeleteQuietly(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (IOException)
        {
            // best effort: a child process may still hold a file for a moment
        }
        catch (UnauthorizedAccessException)
        {
            // best effort
        }
    }

    [GeneratedRegex(@"\bIL\d{4}\b", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex IlWarning();
}
