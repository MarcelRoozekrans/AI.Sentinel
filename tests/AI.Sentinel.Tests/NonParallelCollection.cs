using Xunit;

namespace AI.Sentinel.Tests;

// Tests that mutate process-global state (e.g., environment variables) must not run
// in parallel with each other. Decorate such test classes with [Collection("NonParallel")].
[CollectionDefinition("NonParallel", DisableParallelization = true)]
public sealed class NonParallelCollection
{
}
