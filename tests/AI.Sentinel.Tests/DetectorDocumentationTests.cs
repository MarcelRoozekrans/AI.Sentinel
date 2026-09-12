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

    private sealed record DocRow(string File, string IdCell, string TypeCell);

    /// <summary>Rows of the detector reference tables, found by their header rather than by guessing at
    /// the cell contents. Detector docs contain other tables (tuning notes, false-positive guidance)
    /// whose third column is prose, and an earlier version of this guard skipped any row whose third
    /// cell was not a recognised label — so labelling a detector "Heuristic" made the row invisible.</summary>
    private static IReadOnlyList<DocRow> DetectorReferenceRows()
    {
        var rows = new List<DocRow>();
        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            var inTable = false;
            foreach (var line in File.ReadAllLines(file))
            {
                if (line.StartsWith('|') && line.Contains("| Type |", StringComparison.Ordinal))
                {
                    inTable = true;
                    continue;
                }

                if (!inTable) continue;
                if (!line.StartsWith('|')) { inTable = false; continue; }
                if (IsSeparatorRow(line)) continue;

                var cells = line.Split('|');
                if (cells.Length < 5) continue;

                rows.Add(new DocRow(name, Normalise(cells[1]), cells[3]));
            }
        }

        return rows;
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
        foreach (var row in DetectorReferenceRows())
        {
            foreach (var sid in semanticIds)
            {
                if (row.IdCell.Contains(sid, StringComparison.Ordinal)
                    && row.TypeCell.Contains(RuleBasedLabel, StringComparison.Ordinal))
                {
                    offenders.Add($"{row.File}: {sid}");
                }
            }
        }

        Assert.Empty(offenders);
    }

    /// <summary>Every semantic detector must be documented, and every row documenting one must carry the
    /// marker. Rejecting only the literal "Rule-based" let a new detector be documented with a plain
    /// "Semantic" label, or omitted entirely, while reintroducing the drift this guard prevents.</summary>
    [Fact]
    public void EverySemanticDetector_IsDocumentedAndEveryRowCarriesTheMarker()
    {
        var semanticIds = SemanticDetectorIds();
        AssertDocumentedWithLabel(semanticIds, MarkerLabel);
    }

    /// <summary>A StubDetector always returns Clean, and DetectionPipeline only escalates results at
    /// Severity.Medium or above — so a stub can never fire, with or without an EscalationClient. Any
    /// label other than "Stub" (SEC-08 said "LLM escalation") promises a capability that does not exist.</summary>
    [Fact]
    public void EveryStubDetector_IsDocumentedAsAStub()
    {
        var stubIds = StubDetectorIds();
        Assert.NotEmpty(stubIds);
        AssertDocumentedWithLabel(stubIds, StubLabel);
    }

    /// <summary>Asserts each id appears in the reference tables and that every row for it carries the
    /// expected label — both halves matter, since an undocumented detector drifts just as silently as a
    /// mislabelled one.</summary>
    private static void AssertDocumentedWithLabel(IReadOnlyList<string> ids, string expectedLabel)
    {
        var documented = new HashSet<string>(StringComparer.Ordinal);
        var mislabelled = new List<string>();

        foreach (var row in DetectorReferenceRows())
        {
            foreach (var id in ids)
            {
                if (!row.IdCell.Contains(id, StringComparison.Ordinal)) continue;

                documented.Add(id);
                if (!row.TypeCell.Contains(expectedLabel, StringComparison.Ordinal))
                {
                    mislabelled.Add($"{row.File}: {id} -> '{row.TypeCell.Trim()}'");
                }
            }
        }

        Assert.Empty(mislabelled);

        var undocumented = new List<string>();
        foreach (var id in ids)
        {
            if (!documented.Contains(id)) undocumented.Add(id);
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


    private sealed record DetectorKind(string Id, string TypeName, bool FiresByDefault);

    /// <summary>Detectors that are neither semantic nor stubs but still return Clean in a stock install
    /// because they are gated on caller configuration. SEC-29 OutputSchema needs both
    /// SentinelOptions.ExpectedResponseType and an ISerializerDispatcher, and the library registers
    /// neither. This set is hand-maintained — there is no way to detect a config gate by reflection —
    /// so a new config-gated detector must be added here or the coverage table will overstate it.</summary>
    private static readonly HashSet<string> ConfigGatedDetectorIds = new(StringComparer.Ordinal) { "SEC-29" };

    private static IReadOnlyList<DetectorKind> AllDetectorKinds()
    {
        var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();
        var result = new List<DetectorKind>();
        foreach (var d in provider.GetServices<IDetector>())
        {
            // A semantic detector with a rule layer does fire in a default install: the rule half
            // needs no generator. Treating it as inert let the OWASP table keep claiming LLM01 had no
            // active control after SEC-01 gained one — the guard agreeing with a stale table because
            // its own model was stale.
            var inert = (d is SemanticDetectorBase { HasRuleFastPath: false })
                || d is StubDetector
                || ConfigGatedDetectorIds.Contains(d.Id.Value);
            result.Add(new DetectorKind(d.Id.Value, d.GetType().Name, !inert));
        }

        return result;
    }

    private static bool IsSeparatorRow(string line)
    {
        foreach (var c in line)
        {
            if (c is not ('|' or '-' or ':' or ' ')) return false;
        }

        return true;
    }

    /// <summary>Counts the detectors an OWASP row names, and how many of them fire in a stock install.
    /// Class names are matched backticked: "CovertChannelDetector" (SEC-07) is a suffix of
    /// "EntropyCovertChannelDetector" (SEC-08), so unanchored matching would double-count.</summary>
    private static (int Total, int Active) CountDetectorsNamedIn(string row, IReadOnlyList<DetectorKind> kinds)
    {
        var total = 0;
        var active = 0;
        foreach (var k in kinds)
        {
            var named = row.Contains(k.Id, StringComparison.Ordinal)
                || row.Contains("`" + k.TypeName + "`", StringComparison.Ordinal);
            if (!named) continue;

            total++;
            if (k.FiresByDefault) active++;
        }

        return (total, active);
    }

    /// <summary>The OWASP mapping is the table a compliance reader checks, and it cited detectors that
    /// cannot fire in a stock install. The "Fires by default" verdict is recomputed here from the
    /// registered detectors so the table cannot drift back into claiming coverage it does not have.</summary>
    [Fact]
    public void OwaspMapping_CoverageColumnMatchesTheRegisteredDetectors()
    {
        var kinds = AllDetectorKinds();
        var wrong = new List<string>();
        var filesWithTable = 0;

        foreach (var file in DocFiles())
        {
            var name = Path.GetFileName(file);
            var inTable = false;
            foreach (var line in File.ReadAllLines(file))
            {
                if (line.Contains("Fires by default", StringComparison.Ordinal) && line.StartsWith('|'))
                {
                    inTable = true;
                    filesWithTable++;
                    continue;
                }
                if (inTable && !line.StartsWith('|')) { inTable = false; continue; }
                if (!inTable || !line.StartsWith('|')) continue;

                var cells = line.Split('|');
                if (cells.Length < 4) continue;
                if (IsSeparatorRow(line)) continue;

                var row = Normalise(line);
                var (total, active) = CountDetectorsNamedIn(row, kinds);

                if (total == 0)
                {
                    // Only an explicitly out-of-scope row may name no detector. Anything else means a
                    // renamed detector silently stopped being checked — the drift this guard exists for.
                    if (!row.Contains("out of scope", StringComparison.Ordinal))
                    {
                        wrong.Add($"{name}: '{cells[1].Trim()}' names no known detector");
                    }

                    continue;
                }

                var verdict = cells[^2];
                var expected = active == total ? "yes" : active == 0 ? "none" : "partial";
                if (!verdict.Contains(expected, StringComparison.Ordinal))
                {
                    wrong.Add($"{name}: '{cells[1].Trim()}' says '{verdict.Trim()}', expected {expected} ({active}/{total})");
                }
            }
        }

        Assert.Empty(wrong);
        // A reformatted header would make the whole assertion silently vacuous.
        Assert.Equal(2, filesWithTable);
    }

    /// <summary>#216: the two mapping tables used different Top 10 versions, so "LLM07" meant
    /// "System Prompt Leakage" in one document and "Insecure Plugin Design" in the other. Whoever
    /// cites AI.Sentinel's OWASP coverage in a questionnaire got a different answer depending on
    /// which page they read. Categories and detector membership must both stay identical — the
    /// detector sets had diverged too, and comparing only the category labels would let that half
    /// of the defect return unnoticed.</summary>
    [Fact]
    public void BothOwaspTables_AgreeOnCategoriesAndMembership()
    {
        var kinds = AllDetectorKinds();
        var perFile = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var file in DocFiles())
        {
            var rows = ReadOwaspRows(file, kinds);
            if (rows.Count > 0) perFile[Path.GetFileName(file)] = rows;
        }

        Assert.Equal(2, perFile.Count);

        var names = perFile.Keys.ToList();
        var first = perFile[names[0]];
        var second = perFile[names[1]];

        // Name both files: when this fires, the maintainer has to know which page to correct.
        Assert.True(
            first.SequenceEqual(second, StringComparer.Ordinal),
            $"OWASP tables disagree.{Environment.NewLine}{names[0]}:{Environment.NewLine}  " +
            string.Join($"{Environment.NewLine}  ", first) +
            $"{Environment.NewLine}{names[1]}:{Environment.NewLine}  " +
            string.Join($"{Environment.NewLine}  ", second));

        Assert.Equal(10, first.Count);
    }

    /// <summary>Renders each OWASP row as "LLM0n threat | id,id,id" so two tables written in
    /// different styles — the README names classes, the website names ids — are comparable.</summary>
    private static List<string> ReadOwaspRows(string file, IReadOnlyList<DetectorKind> kinds)
    {
        var rows = new List<string>();
        var inTable = false;

        foreach (var line in File.ReadAllLines(file))
        {
            if (line.Contains("Fires by default", StringComparison.Ordinal) && line.StartsWith('|'))
            {
                inTable = true;
                continue;
            }

            if (!inTable) continue;
            if (!line.StartsWith('|')) { inTable = false; continue; }
            if (IsSeparatorRow(line)) continue;

            var cells = line.Split('|');
            if (cells.Length < 3) continue;

            var label = Normalise(cells[1]).Replace("**", string.Empty, StringComparison.Ordinal);
            if (!label.StartsWith("LLM", StringComparison.Ordinal)) continue;

            // Split on the first space rather than slicing at a fixed index: a footnote marker or a
            // typo would otherwise produce an opaque mismatch, or throw.
            var space = label.IndexOf(' ', StringComparison.Ordinal);
            var id = space < 0 ? label : label[..space];
            var threat = space < 0 ? Normalise(cells[2]) : label[(space + 1)..].Trim();

            var row = Normalise(line);
            var members = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var k in kinds)
            {
                if (row.Contains(k.Id, StringComparison.Ordinal)
                    || row.Contains("`" + k.TypeName + "`", StringComparison.Ordinal)
                    || row.Contains("(" + k.TypeName.Replace("Detector", string.Empty, StringComparison.Ordinal) + ")", StringComparison.Ordinal))
                {
                    members.Add(k.Id);
                }
            }

            rows.Add($"{id} {threat} | {string.Join(",", members)}");
        }

        return rows;
    }

    /// <summary>A category the mapping tables declare out of scope must not be claimed as covered
    /// anywhere else. The tables agreeing with each other is not enough: OPS-11 was annotated
    /// "(OWASP LLM04)" on the operational detectors page under the old 2023 numbering, so a
    /// compliance reader was told LLM04 was covered on one page and uncovered on two others —
    /// #216's defect relocated to a third document rather than removed.</summary>
    [Fact]
    public void NoDocumentClaimsACategoryTheTablesCallOutOfScope()
    {
        var outOfScope = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var file in DocFiles())
        {
            foreach (var line in File.ReadAllLines(file))
            {
                if (!line.StartsWith('|')) continue;
                if (!line.Contains("out of scope", StringComparison.Ordinal)) continue;

                var label = Normalise(line.Split('|')[1]).Replace("**", string.Empty, StringComparison.Ordinal);
                if (label.StartsWith("LLM", StringComparison.Ordinal))
                {
                    var space = label.IndexOf(' ', StringComparison.Ordinal);
                    outOfScope.Add(space < 0 ? label : label[..space]);
                }
            }
        }

        Assert.NotEmpty(outOfScope);

        var offenders = new List<string>();
        foreach (var file in AllDocumentationFiles())
        {
            var text = File.ReadAllText(file);
            foreach (var category in outOfScope)
            {
                if (text.Contains("OWASP " + category, StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(file)} claims OWASP {category}, which the mapping tables call out of scope");
                }
            }
        }

        Assert.Empty(offenders);
    }

    /// <summary>Every markdown file that could carry an OWASP claim, not just the detector tables.</summary>
    private static IReadOnlyList<string> AllDocumentationFiles()
    {
        var root = RepoRoot();
        var files = new List<string> { Path.Combine(root.FullName, "README.md") };
        var docs = Path.Combine(root.FullName, "website", "docs");
        if (Directory.Exists(docs))
        {
            files.AddRange(Directory.GetFiles(docs, "*.md", SearchOption.AllDirectories));
        }

        return files.Where(File.Exists).ToList();
    }
}
