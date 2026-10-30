using AI.Sentinel.Detection;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>The reviewer knows what a detector looks for only through its criterion, so every reviewable
/// detector must state one that is usable in a prompt and that tells it apart from the others (#511).</summary>
public class ReviewCriterionTests
{
    private static IReadOnlyList<(string Name, string Criterion)> Criteria()
    {
        var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();
        var registered = provider.GetServices<IDetector>().ToDictionary(d => d.GetType());

        var reviewableTypes = typeof(IDetector).Assembly.GetTypes()
            .Where(t => t is { IsAbstract: false, IsInterface: false } && typeof(IDetector).IsAssignableFrom(t))
            .Where(t => typeof(SemanticDetectorBase).IsAssignableFrom(t) || typeof(ILlmEscalatingDetector).IsAssignableFrom(t))
            .ToList();
        Assert.NotEmpty(reviewableTypes);

        var result = new List<(string, string)>();
        foreach (var type in reviewableTypes)
        {
            Assert.True(registered.TryGetValue(type, out var detector), $"{type.Name} is not registered by AddAISentinel, so the test cannot reach it.");
            var criterion = detector switch
            {
                SemanticDetectorBase semantic => semantic.Criterion,
                ILlmEscalatingDetector escalating => escalating.ReviewCriterion,
                _ => throw new InvalidOperationException(type.Name),
            };
            result.Add((type.Name, criterion));
        }

        return result;
    }

    [Fact]
    public void EveryReviewableDetector_HasADistinctCriterion()
    {
        var criteria = Criteria();

        foreach (var (name, criterion) in criteria)
        {
            Assert.False(string.IsNullOrWhiteSpace(criterion), $"{name} has a blank criterion.");
            Assert.InRange(criterion.Length, 40, 400);
            Assert.DoesNotContain('{', criterion);
            Assert.DoesNotContain('}', criterion);
        }

        var duplicates = criteria.GroupBy(c => c.Criterion, StringComparer.Ordinal).Where(g => g.Count() > 1)
            .Select(g => string.Join(" and ", g.Select(c => c.Name))).ToList();
        Assert.True(duplicates.Count == 0, "Detectors share a criterion: " + string.Join("; ", duplicates));
    }
}
