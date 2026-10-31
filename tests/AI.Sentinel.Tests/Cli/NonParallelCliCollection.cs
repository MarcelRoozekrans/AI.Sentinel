using Xunit;

namespace AI.Sentinel.Tests.Cli;

[CollectionDefinition(nameof(NonParallelCliCollection), DisableParallelization = true)]
public sealed class NonParallelCliCollection;
