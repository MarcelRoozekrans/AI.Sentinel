---
sidebar_position: 1
title: SDK overview
---

# Custom Detector SDK

`AI.Sentinel.Detectors.Sdk` is the toolkit for writing and testing your own detectors:

- **`SentinelContextBuilder`** — fluent factory for `SentinelContext` instances
- **`FakeEmbeddingGenerator`** — deterministic char-bigram generator for testing semantic detectors offline
- **`DetectorTestBuilder`** — fluent assertion helper: `WithDetector<T>().WithPrompt(...).ExpectDetection(Severity.High)`
- **`DetectorAssertionException`** — test-framework-neutral exception thrown by failing assertions

You don't need this package to *write* a detector — `IDetector` is in `AI.Sentinel` itself. You need this package to *test* one cleanly.

```bash
dotnet add package AI.Sentinel.Detectors.Sdk
```

> Full SDK guide — coming soon. See [Writing a detector](./writing-a-detector) and [DetectorTestBuilder](./detector-test-builder).
