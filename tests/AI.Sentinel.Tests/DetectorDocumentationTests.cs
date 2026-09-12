using System.Reflection;
using AI.Sentinel.Detection;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

/// <summary>Guards the detector tables in the docs against drifting from the source (#170).
/// A row labelled "Rule-based" reads as "always active"; for a SemanticDetectorBase subclass
/// that is false — it returns Clean until an EmbeddingGenerator is configured.</summary>
public class DetectorDocumentationTests
{
    private const string RuleBasedLabel = "Rule-based";

    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AI.Sentinel.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.SkipWhen(dir is null, "Repository root not found — docs are not present in this layout.");
        return dir!;
    }

    private static IReadOnlyList<string> DocFiles()
    {
        var root = RepoRoot();
        var files = new List<string> { Path.Combine(root.FullName, "README.md") };
        var detectorDocs = Path.Combine(root.FullName, "website", "docs", "detectors");
        if (Directory.Exists(detectorDocs))
        {
            files.AddRange(Directory.GetFiles(detectorDocs, "*.md"));
        }

        return files.Where(File.Exists).ToList();
    }

    /// <summary>Detector ids are written with a non-breaking hyphen in some tables.</summary>
    private static string Normalise(string cell) =>
        cell.Replace('‑', '-').Replace('‐', '-').Replace('–', '-').Trim();

    private static IReadOnlyList<string> SemanticDetectorIds()
    {
        var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();
        return provider.GetServices<IDetector>()
            .Where(d => d is SemanticDetectorBase)
            .Select(d => d.Id.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    [Fact]
    public void SemanticDetectors_AreNotDocumentedAsRuleBased()
    {
        var semanticIds = SemanticDetectorIds();
        Assert.NotEmpty(semanticIds);

        var offenders = new List<string>();

        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            foreach (var line in File.ReadAllLines(file))
            {
                if (!line.StartsWith('|')) continue;

                var rawCells = line.Split('|');
                if (rawCells.Length < 4) continue;

                var idCell = Normalise(rawCells[1]);
                string? matchedId = null;
                for (var i = 0; i < semanticIds.Count; i++)
                {
                    if (idCell.Contains(semanticIds[i], StringComparison.Ordinal))
                    {
                        matchedId = semanticIds[i];
                        break;
                    }
                }

                if (matchedId is null) continue;

                foreach (var cell in rawCells)
                {
                    if (cell.Contains(RuleBasedLabel, StringComparison.Ordinal))
                    {
                        offenders.Add($"{name}: {matchedId}");
                        break;
                    }
                }
            }
        }

        Assert.Empty(offenders);
    }
}
