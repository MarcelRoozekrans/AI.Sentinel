using System.Reflection;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

/// <summary>Guards the detector tables in the docs against drifting from the source (#170).
/// A row labelled "Rule-based" reads as "always active"; for a SemanticDetectorBase subclass
/// that is false — it returns Clean until an EmbeddingGenerator is configured.</summary>
public class DetectorDocumentationTests
{
    private const string RuleBasedLabel = "Rule-based";
    private const string MarkerLabel = "⚠️";
    private const string StubLabel = "Stub";

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

    /// <summary>Detector docs contain other tables (tuning notes, false-positive guidance) whose third
    /// column is prose. Only treat a row as a Type row when that cell holds a known type label.</summary>
    private static bool IsTypeCell(string cell)
    {
        var v = cell.Trim();
        return v.StartsWith("Rule-based", StringComparison.Ordinal)
            || v.StartsWith("Semantic", StringComparison.Ordinal)
            || v.StartsWith("LLM escalation", StringComparison.Ordinal)
            || v.StartsWith("Stub", StringComparison.Ordinal);
    }

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

                if (IsTypeCell(rawCells[3]) && rawCells[3].Contains(RuleBasedLabel, StringComparison.Ordinal))
                {
                    offenders.Add($"{name}: {matchedId}");
                }
            }
        }

        Assert.Empty(offenders);
    }

    /// <summary>Every semantic detector must be documented, and every row documenting one must carry
    /// the marker. Rejecting only the literal "Rule-based" let a new detector be documented with a
    /// plain "Semantic" label, or omitted entirely, while reintroducing the drift this guard prevents.
    /// Aggregated across files because the website splits the tables by category.</summary>
    [Fact]
    public void EverySemanticDetector_IsDocumentedAndEveryRowCarriesTheMarker()
    {
        var semanticIds = SemanticDetectorIds();
        var documented = new HashSet<string>(StringComparer.Ordinal);
        var unmarked = new List<string>();

        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            foreach (var line in File.ReadAllLines(file))
            {
                if (!line.StartsWith('|')) continue;
                var cells = line.Split('|');
                if (cells.Length < 4) continue;

                var idCell = Normalise(cells[1]);
                foreach (var sid in semanticIds)
                {
                    if (!idCell.Contains(sid, StringComparison.Ordinal)) continue;
                    if (!IsTypeCell(cells[3])) continue;

                    documented.Add(sid);
                    if (!cells[3].Contains(MarkerLabel, StringComparison.Ordinal))
                    {
                        unmarked.Add($"{name}: {sid} -> '{cells[3].Trim()}'");
                    }
                }
            }
        }

        Assert.Empty(unmarked);

        var undocumented = new List<string>();
        foreach (var sid in semanticIds)
        {
            if (!documented.Contains(sid)) undocumented.Add(sid);
        }

        Assert.Empty(undocumented);
    }

    private static IReadOnlyList<string> StubDetectorIds()
    {
        var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();
        return provider.GetServices<IDetector>()
            .Where(d => d is StubDetector)
            .Select(d => d.Id.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>A StubDetector always returns Clean, and DetectionPipeline only escalates results at
    /// Severity.Medium or above — so a stub can never fire, with or without an EscalationClient. Any
    /// label other than "Stub" (SEC-08 said "LLM escalation") promises a capability that does not exist.</summary>
    [Fact]
    public void EveryStubDetector_IsDocumentedAsAStub()
    {
        var stubIds = StubDetectorIds();
        Assert.NotEmpty(stubIds);

        var mislabelled = new List<string>();

        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            foreach (var line in File.ReadAllLines(file))
            {
                if (!line.StartsWith('|')) continue;
                var cells = line.Split('|');
                if (cells.Length < 4 || !IsTypeCell(cells[3])) continue;

                var idCell = Normalise(cells[1]);
                foreach (var sid in stubIds)
                {
                    if (idCell.Contains(sid, StringComparison.Ordinal)
                        && !cells[3].Contains(StubLabel, StringComparison.Ordinal))
                    {
                        mislabelled.Add($"{name}: {sid} -> '{cells[3].Trim()}'");
                    }
                }
            }
        }

        Assert.Empty(mislabelled);
    }

    private sealed record DetectorKind(string Id, string TypeName, bool FiresByDefault);

    private static IReadOnlyList<DetectorKind> AllDetectorKinds()
    {
        var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();
        var result = new List<DetectorKind>();
        foreach (var d in provider.GetServices<IDetector>())
        {
            var inert = d is SemanticDetectorBase || d is StubDetector;
            result.Add(new DetectorKind(d.Id.Value, d.GetType().Name, !inert));
        }

        return result;
    }

    /// <summary>The OWASP mapping is the table a compliance reader checks, and it cited detectors that
    /// cannot fire in a stock install. The "Fires by default" verdict is recomputed here from the
    /// registered detectors so the table cannot drift back into claiming coverage it does not have.</summary>
    [Fact]
    public void OwaspMapping_CoverageColumnMatchesTheRegisteredDetectors()
    {
        var kinds = AllDetectorKinds();
        var wrong = new List<string>();

        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            var inTable = false;
            foreach (var line in File.ReadAllLines(file))
            {
                if (line.Contains("| Fires by default |", StringComparison.Ordinal)) { inTable = true; continue; }
                if (inTable && !line.StartsWith('|')) { inTable = false; continue; }
                if (!inTable || !line.StartsWith('|')) continue;

                var cells = line.Split('|');
                if (cells.Length < 4) continue;

                var row = Normalise(line);
                var total = 0;
                var active = 0;
                foreach (var k in kinds)
                {
                    var named = row.Contains(k.Id, StringComparison.Ordinal)
                        || row.Contains(k.TypeName, StringComparison.Ordinal);
                    if (!named) continue;
                    total++;
                    if (k.FiresByDefault) active++;
                }

                if (total == 0) continue;   // out-of-scope rows

                var verdict = cells[^2];
                var expected = active == total ? "yes" : active == 0 ? "none" : "partial";
                if (!verdict.Contains(expected, StringComparison.Ordinal))
                {
                    wrong.Add($"{name}: '{cells[1].Trim()}' says '{verdict.Trim()}', expected {expected} ({active}/{total})");
                }
            }
        }

        Assert.Empty(wrong);
    }
}
