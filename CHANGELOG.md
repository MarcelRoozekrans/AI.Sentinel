# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Subsequent entries are generated automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/).

## [1.2.0](https://github.com/MarcelRoozekrans/AI.Sentinel/compare/v1.1.0...v1.2.0) (2026-04-29)


### Features

* **approvals:** ApprovalSpec / ApprovalContext / PendingRequest records ([8767c40](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8767c40e0fa0f248401db1f44b664a325d216103))
* **approvals:** chat-client middleware blocks-and-waits on RequireApproval ([43fa1cc](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/43fa1ccbce213e8f72c40d5f146ba965ec013e01))
* **approvals:** DefaultToolCallGuard delegates to IApprovalStore for approval bindings ([4534397](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/453439706f0c686909bb1540cc8ee73fed86e9a3))
* **approvals:** IApprovalStore + IApprovalAdmin contracts + ApprovalState ([b8722a6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b8722a63625d2cb84ce1d1eae567703d201a4557))
* **approvals:** InMemoryApprovalStore (IApprovalStore + IApprovalAdmin) ([6b19aaa](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6b19aaad6372cb824d9b7972fde1ed279fb66ff7))
* **approvals:** opts.RequireApproval(toolPattern, spec) registration verb ([cccebbc](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cccebbcec59aa22386489b3e62f7162e70a9c3dc))
* **approvals:** Stage 1 — core abstraction + InMemoryApprovalStore + middleware ([3ac561d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/3ac561d9c59f689eb0de2bc8f978af432dd6588a))
* **authz:** RequireApproval decision tier + AsBinary fold helper ([79e4583](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/79e4583d47b3f1657ee07d8281e729bf4f3e0c81))
* **sqlite:** MaxDatabaseSizeBytes cap on SqliteAuditStore ([62a9a23](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/62a9a23d14ade9ddcff3b661a122a95f93b47878))


### Bug Fixes

* **approvals:** chat-client re-queries guard after WaitForDecisionAsync — fixes stacked-binding skip ([90f71d3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/90f71d38a3a36c9ad9ef0c64f39683b514fecc14))
* **approvals:** InMemoryApprovalStore dedupe cleanup + TOCTOU lock + persist approverId ([cd7f152](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cd7f152bd77f1ec104be7b7de7eb6098c8b708e5))
* **aspnetcore:** mobile dashboard polish — drop Hash column, scroll affordance ([7aa5a15](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7aa5a15815b9fe83b53712c85aa977e168541d33))

## [1.1.0](https://github.com/MarcelRoozekrans/AI.Sentinel/compare/v1.0.1...v1.1.0) (2026-04-29)


### Features

* **aspnetcore:** MapAISentinel for endpoint-routing-friendly mounts ([cf6a03c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cf6a03ce0a996d7b41ea65ad8cabedaa16f0371b))
* **samples:** Demo:SeedDashboard pre-populates audit on startup ([a095449](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/a095449039e30bcf445e084122a0edf120e7616b))


### Bug Fixes

* **aspnetcore:** dashboard endpoint-routing mount + mobile layout + a11y ([2f7834c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2f7834c29dc3b2b8ccdec75654e801468ecc3f52))
* **aspnetcore:** mobile dashboard layout, empty-state row, a11y tabs ([219df7d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/219df7dd791dc66993a5c5b55721733a75c4dcb6))
* **aspnetcore:** TRS gauge ring colour updates with stage ([d51d5a5](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d51d5a534b97d8809e52cfa6a52313b8666a4d8a))
* **samples:** ChatApp uses MapAISentinel + absolute SignalR hub URL ([484d1e7](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/484d1e70219f537c8275bb05349ee937b3047224))

## [1.0.1](https://github.com/MarcelRoozekrans/AI.Sentinel/compare/v1.0.0...v1.0.1) (2026-04-29)


### Bug Fixes

* **cli:** clear inherited TargetFrameworks in AI.Sentinel.Cli ([dd1baa6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/dd1baa6a6f7dd245f0e692255331d71f47a6daae))

## 1.0.0 (2026-04-29)


### Features

* add 13 new detectors (SEC-23–28, HAL-06–08, OPS-12–15) + fix 5 more ID bugs ([fdc4766](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/fdc4766508e271875ab1fd589df604691e5a40fa))
* add AlertDeduplicationWindow option for configurable alert suppression ([f2f4d20](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/f2f4d2001fc969a83867094743c74d0645167fb1))
* add AspNetCore AddAISentinel extension ([2e7b57b](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2e7b57b03918bce8c1ead79369f62df46aee0993))
* add audit trail with ring buffer store ([473af11](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/473af11e29a91b7755d0a1ab4439e86380191bd8))
* add core value objects (AgentId, SessionId, DetectorId, ThreatRiskScore) ([e726d47](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/e726d47d3d574b64d052ef28074d29fe26ec85f1))
* add detection pipeline with parallel execution and LLM escalation ([09da65d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/09da65d140006346e1dc45073a5da839d2aa131e))
* add detection types (Severity, DetectionResult, SentinelContext, IDetector) ([ce1da16](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ce1da167fe03e7a0c2a0a39c88b70606fd9c452a))
* add embedded dashboard with TRS gauge and live feed ([4324ccb](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4324ccb298bbc56924dabf7778a681f31b5963e0))
* add ExpectedResponseType option + ZeroAlloc.Serialisation dep ([db5c58e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/db5c58eadbbab2f4b45bc867778a4729cfaf44bf))
* add HAL-01..05 hallucination detectors ([2b1853c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2b1853cff5b926bc7d691cb9f0e234a4d90fce4e))
* add intervention engine with SentinelException and notifications ([fcf0812](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/fcf08125c84621e2b7b4d02474891f1c1524a4c4))
* add lazy sweep to DeduplicatingAlertSink ([cb3c0dc](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cb3c0dcc89a2fc8399f9dae4d375610c8e0d4abe))
* add lazy sweep to SentinelPipeline rate limiter dictionary ([46164ae](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/46164ae38ab4aadc7205050fabd2843c72364a25))
* add MaxCallsPerSecond and BurstSize to SentinelOptions ([b7a449e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b7a449e5b9d781f4694172d7aaae88c038a05aec))
* add OPS-01..08 operational detectors ([c932ebc](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c932ebc575a0ac887bd14b35e150bb14881edb03))
* add optional webhook alert sink (IAlertSink / WebhookAlertSink) ([78204e3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/78204e3532c5c8fdcdce95637a2e37d9837bb0b0))
* add OutputSchemaDetector (SEC-29) ([ebc5ecf](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ebc5ecf6b6da6e7cbbde98bbff4c4ca306e41bc9))
* add per-session rate limiting to SentinelPipeline ([d9df0b8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d9df0b8b67d59297f0864020eade986d63828f86))
* add RateLimitExceeded error case and ZeroAlloc.Resilience package ([e9fcb5d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/e9fcb5d7ee0fd98cdf1f4192f8ad6814b88f7695))
* add SEC-01..04 (prompt injection, credential, tool poisoning, exfiltration) ([e744608](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/e744608f9a29fd2fe761f381c0cc46422b84cb37))
* add SEC-05..17 security detectors ([e6e3e3f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/e6e3e3f2982305f13695b3904a87d2900245ec23))
* add SentinelChatClient middleware and DI registration ([bb3daee](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/bb3daeeb6300aef994cb1e57bc240bd2f669a3d0))
* add SentinelError discriminated union with ToException() ([0939165](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0939165065b461132ad61d914b70d623d1c965bc))
* add SentinelOptions with source-generated validation ([50cac37](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/50cac37dff6b3fab180b95aeffed48f093594d15))
* add SentinelPipeline with Result-returning GetResponseResultAsync ([bf10966](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/bf109661f2398494641591e34809ee798618f8d3))
* add SessionId to SentinelError.ThreatDetected for deduplication and webhook correlation ([732e7ef](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/732e7efbfa6ba42ab8f43001f3178e10eb478dff))
* add SessionIdleTimeout option with validation ([c90c958](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c90c958098174078730f835a37106da84d9e4b9d))
* add streaming pipeline support with full detection scan ([ca28b5f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ca28b5f7b95e981d9425fb1de19794b801985681))
* add SystemPromptLeakageDetector (SEC-20) ([e4e601e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/e4e601ea20e7366d330a9e0d4a48e7b51d9d4208))
* add ZeroAlloc.Inject package reference ([2ea538f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2ea538f9d1715254e704c4eae8f9b0c0dc69734c))
* add ZeroAlloc.Telemetry package reference ([10a8c40](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/10a8c408f5618e6822510391aacf0e3824d1bf1d))
* annotate hallucination and operational detectors with [Singleton] ([c5c6da0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c5c6da0c930f2f856d8ff45db7e0d26ff6193ab5))
* annotate security detectors with [Singleton] for DI generation ([9258b85](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/9258b85fc723c46c220bf228e84aff11abd5ab69))
* **aspnetcore:** ClaimsPrincipalSecurityContext for HTTP-driven caller identity ([ca38a0e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ca38a0e6b80400b918ef4e2ff3a0d65a1fddf9e1))
* **audit:** AzureSentinelAuditForwarder — Logs Ingestion API forwarding in new AI.Sentinel.AzureSentinel package ([68cd6a5](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/68cd6a530e207db544233db91b51a7052c6c1446))
* **audit:** IAuditForwarder + BufferingAuditForwarder&lt;T&gt; decorator ([dbc5d56](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/dbc5d563788a65fa6e5723e4c4b922209696ddc1))
* **audit:** NdjsonFileAuditForwarder + AddSentinelNdjsonFileForwarder DI extension ([194e4f9](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/194e4f9c2418c3f40ea59dde6dbd5c659e232f00))
* **audit:** OpenTelemetryAuditForwarder — vendor-neutral via OTel collector in new AI.Sentinel.OpenTelemetry package ([2600676](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2600676e0acac25bbfd6b0f758403957cd5cef39))
* **audit:** SentinelPipeline forwards every audit entry to registered IAuditForwarders ([00cdd55](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/00cdd55c0fc7e9a570daba42f35ce1cc05e8b433))
* **audit:** SqliteAuditStore — persistent audit storage in new AI.Sentinel.Sqlite package ([d690be9](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d690be99f5111538a87fb3b69188191b322ac870))
* **authz:** AuditEntry.AuthorizationDeny extension for AUTHZ-DENY entries ([2a52ad2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2a52ad21cc12b0af6e30454c6e8e3e5b5de6da94))
* **authz:** IAuthorizationPolicy + ToolCallAuthorizationPolicy base + [AuthorizationPolicy] ([b8d476e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b8d476e2462e3d803544053b40ed51a6c834fc60))
* **authz:** ISecurityContext + AnonymousSecurityContext + IToolCallSecurityContext ([8422a48](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8422a4841b049cb870c3126794e9bce436d6f973))
* **authz:** IToolCallGuard + DefaultToolCallGuard + binding resolver + AuthorizationDecision ([2beb7d2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2beb7d255aa4ac741f57b8b98f0f6eb9ca14b756))
* **authz:** sample policies — AdminOnlyPolicy + NoSystemPathsPolicy ([72910b6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/72910b6101643df9065d0a0b3c32473ef2068a48))
* **authz:** SentinelOptions integration + DI registration + startup warnings + ToolCallAuthorizationException ([c5c851d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c5c851d28caef89fd9f3306b6f9ee4acf2fd1c88))
* **authz:** UseToolCallAuthorization() ChatClientBuilder extension + delegating client ([11d55b1](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/11d55b1a427d6e7d4d6df83f43315cbeabea9e54))
* **benchmarks:** add AuditStoreBenchmarks ([01fe881](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/01fe8815d472a45da990b08394e999dfa7cb607c))
* **benchmarks:** add BenchmarkDotNet global config ([f9e13a6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/f9e13a61187c493a9fc35886f88ecb8a57de8b9c))
* **benchmarks:** add DetectorBenchmarks ([6cc384d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6cc384d2ee8cabe03686a3471f966179d6b8504c))
* **benchmarks:** add E2EBenchmarks ([8799322](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/879932284b789704ea0aad5ab85055fa4ce90eb9))
* **benchmarks:** add MessageFactory harness helper ([ca5f1a1](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ca5f1a1106baf930846df30f7976a107d2894339))
* **benchmarks:** add NoOpChatClient harness stub ([b42952c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b42952cfa7dc8b41b43db579ffb905402fe4023b))
* **benchmarks:** add PipelineBenchmarks ([cb5a1b3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cb5a1b3c1f305471e7026899f27c214cfce2624e))
* **benchmarks:** add PipelineFactory harness helper ([2fc39a6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2fc39a63c6e8fa274d5c5179c9bdfca469bc0299))
* **benchmarks:** add SentinelOptionsFactory harness helper ([123da33](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/123da3359d76e51c01e0bdf1a9181650a04583b4))
* **benchmarks:** audit-forwarders v1 — SqliteAuditStore parametrize + PipelineWithForwarders coverage ([d113cf8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d113cf84984aef1025abbf52e29d07084980e07f))
* **benchmarks:** MCP proxy v1.1 hot-path coverage — Truncate + MIME match + StderrLogger format ([1bf3069](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/1bf30692446d74c7e0011822bb839a61864c94ec))
* **benchmarks:** scaffold AI.Sentinel.Benchmarks project ([9782a90](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/9782a907b6130777ecb49afe7eccb9957d9ef1b2))
* **benchmarks:** semantic detection variants + cache micro-benchmarks + fix misleading null-generator labels ([292807f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/292807f8d316f27d5cb964519fdac56b7213560e))
* **benchmarks:** update PipelineFactory for SemanticDetectorBase constructors + VectorRetrieval ([26b1650](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/26b16504ffeb3df85b5b81318344f179c4a6a576))
* **claude-code:** add HookAdapter, HookPipelineRunner, HookConfig, HookSeverityMapper ([4d3a202](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4d3a20246b4472266607d6075104d9f4343e5368))
* **claude-code:** add Verbose to HookConfig + SENTINEL_HOOK_VERBOSE parsing ([349e012](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/349e0121b1bc2f0628c93535a99c97ef20f8822f))
* **claude-code:** implement sentinel-hook CLI entrypoint ([6369ce5](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6369ce515932e58958a068e7096e7ac6ee3ddf0b))
* **claudecode:** IToolCallGuard integration on PreToolUse ([b85d397](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b85d39747580d266d2f438f9ca7ae42c91979ed6))
* **cli:** add --expect, --min-severity, --baseline flags ([713bba8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/713bba885df7a7c266db46faae992c2e84ab1b29))
* **cli:** add ConversationLoader with OpenAI + NDJSON formats ([83fe3cd](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/83fe3cd188d7e4f61b234a4707460ddaa51e1804))
* **cli:** add ReplayRunner and ReplayResult types ([ae1308a](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ae1308a28b9a67c2b0e79a501b9c05542366803e))
* **cli:** add scan command with text + JSON output ([acb6033](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/acb60337439045ab478212e3773592e1b7c664f7))
* **cli:** add SentinelReplayClient ([53438f3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/53438f34284eda6e6acc1139b5b6fae79993b870))
* **cli:** MCP severity flags + scope CancelKeyPress handler ([9c10ba3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/9c10ba35722657ddc9b50b8f8fd3664a4bbf2046))
* **cli:** SENTINEL_HOOK_VERBOSE one-liner stderr diagnostics ([79f1007](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/79f10071b693912088ab3738ddd82d1f1aa62b19))
* **copilot:** add CopilotHookAdapter ([cf7a6b5](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/cf7a6b587af404291b450e7c12fa71a8e9898c98))
* **copilot:** implement sentinel-copilot-hook CLI entrypoint ([9040780](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/90407809d0375171fe5a8bbac9195a7bad8ed9c4))
* **copilot:** IToolCallGuard integration on preToolUse ([c3dcf7e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c3dcf7e810eec185eb5de72fa2dc0fda290ac149))
* **dashboard:** Authorization filter chip + AUTHZ-DENY row styling ([38ab075](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/38ab0757e3a52a212bf61227aebd0b1d0a206c6d))
* declare ZeroAllocInject assembly attribute ([4bafd6c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4bafd6c8554797368a296db8ce19bbbd7489533f))
* **detection:** DetectorConfiguration + opts.Configure&lt;T&gt;() — registration-side surface ([71cb249](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/71cb249c5c181eac00416e5afa027deae7252cbc))
* **detection:** IEmbeddingCache + InMemoryLruEmbeddingCache ([72e2437](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/72e24374ecd4d4b2d799f188f2e214953a82852d))
* **detection:** named AddAISentinel(name, configure) overload — keyed-DI registration ([29f03e2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/29f03e21621d3968be6d9dfa4f27f1adda82f750))
* **detection:** named UseAISentinel(name) — chat client picks named pipeline at construction ([1471b06](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/1471b06a9ac8546ac9df2799ad4fb0557a50ee00))
* **detection:** opts.AddDetector&lt;T&gt;() ergonomic registration with factory overload ([7eebb86](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7eebb867c456d1661b3866ce8bdd45fc2b47775e))
* **detection:** pipeline applies SeverityFloor/SeverityCap to firing results (Configure&lt;T&gt;) ([3684812](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/3684812e06a11e8f5fc947b1d5b84c4694bff285))
* **detection:** pipeline skips disabled detectors at construction (Configure&lt;T&gt;(c =&gt; c.Enabled = false)) ([360c08e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/360c08e1fddeabeb124cc9d58f3008e7e55dad6c))
* **detection:** SemanticDetectorBase — cosine similarity over IEmbeddingGenerator ([6613f59](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6613f5980b35049dfc592c8ddcf48c4159eaa3b2))
* **detectors:** HAL-09 UncertaintyPropagationDetector ([fffa1ed](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/fffa1edfffffa63c487b38507ebd49d73c38d819))
* **detectors:** migrate all 23 security detectors to SemanticDetectorBase ([ad8cc9b](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ad8cc9bf9fdd928c18365ad414abbd39f23b4353))
* **detectors:** migrate hallucination semantic detectors to SemanticDetectorBase ([0f79ff9](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0f79ff96ee981bb5767cd11c7912d1b0686b6ab0))
* **detectors:** migrate operational semantic detectors to SemanticDetectorBase ([4555819](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/45558194d861c620df1d1c77e36234e4b0367bc4))
* **detectors:** OPS-09 TruncatedOutputDetector ([7444624](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7444624020ceabe64e4eb034b42096555b5ab340))
* **detectors:** OPS-10 WaitingForContextDetector ([4ab09f7](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4ab09f78b2be46363a9dd9e0ca03ecfa7fe26233))
* **detectors:** OPS-11 UnboundedConsumptionDetector ([db8827f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/db8827f24fce7a915e0318ffb288afde09322fe1))
* **detectors:** SEC-18 ToolDescriptionDivergenceDetector (stub) ([b069d07](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b069d0783124c63a155567fd5a91f9ec14ec071b))
* **detectors:** SEC-19 ToolCallFrequencyDetector ([3859ea6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/3859ea6e6636f5d64da41501ddd56dbe68dc499b))
* **detectors:** SEC-21 ExcessiveAgencyDetector ([60110e4](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/60110e4ac988aeb93488b413df2e16627e31824d))
* **detectors:** SEC-22 HumanTrustManipulationDetector ([c1c5150](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c1c5150aa60cf3b6b71bd729dd22a449fed65b8f))
* **detectors:** SEC-30 ShorthandEmergenceDetector ([6c47c41](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6c47c41f320ad0a302b4e30ee9457e6a05ca66ca))
* **detectors:** VectorRetrievalPoisoningDetector — OWASP LLM08 coverage ([19b4224](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/19b42245ca14370a3993774fcf8a5566a2d6f19a))
* enrich sentinel.scan spans with severity tags; add sentinel.threats counter per severity ([9021c45](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/9021c457c88819b29bc9d3ad3a6270322b871aa4))
* expose BuildSentinelPipeline factory for Result-API callers ([d146f76](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d146f7658c126af59a444f1841cea642e4059608))
* extract IDetectionPipeline; annotate interfaces for ZeroAlloc.Telemetry generation ([fafcbd6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/fafcbd623fe8591468a4ba33080f922d3b470f12))
* implement Chat.razor and ChatMessageDto DTO ([7ab2528](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7ab2528a239c6f9766ca79a65d49bdf6c5aa879c))
* implement ChatHub and Program.cs for ChatApp.Server ([0a08ab4](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0a08ab4aae3b910d27dea1d1c0b4c4f768fe6b93))
* implement ConsoleDemo with OpenRouter + AI.Sentinel streaming loop ([8106ab0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8106ab03a5adf2c334bf02a1c89dcf32ed4f3878))
* implement DeduplicatingAlertSink; wire as outermost IAlertSink in DI ([d5c6ab8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d5c6ab80e873208bb1266cda2bc619774083f6cc))
* include SessionId in WebhookAlertSink JSON payload ([b65532b](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b65532bdf5b49a4556369a69e0adf5417e4e7a31))
* link ChatApp.Client into ChatApp.Server as hosted WASM; add README ([050cf71](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/050cf7197f31d228dbf2591bbc4a3db1f0104ae0))
* **mcp:** forward-only McpProxy wired via McpServer + McpClient ([55815b0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/55815b06241dfc1645342f5c29dd92f30125f4f6))
* **mcp:** intercept prompts/get — block on injection in response ([8e00d35](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8e00d3557b06d7d81db5b3486738824a350b5434))
* **mcp:** intercept tools/call — block on injection in args or result ([7d2f0f3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7d2f0f3acfd65b19258548c287f4f8eb61f2bb84))
* **mcp:** IToolCallGuard integration on tools/call + env-var caller resolver ([6d323fb](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/6d323fb4e58379fb419f61e670e088c3ed0a5d31))
* **mcp:** McpPipelineFactory with security + all detector presets ([05c73b2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/05c73b208fa615a33c876318c8b5be9ebad1ba4c))
* **mcp:** MessageBuilder maps MCP models to ChatMessage[] for scanning ([638f4ce](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/638f4ce47db8e1e68d30ed91224a3dfb3b1e8a27))
* **mcp:** ResourceReadInterceptor + MIME allowlist + capability mirroring ([d4c4a0b](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d4c4a0b889f24e32196f93044e9fd9d2bd27f95e))
* **mcp:** scaffold sentinel-mcp CLI with usage stub ([ba2ead6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ba2ead6b4d0c7e3f9365c6421125b1747db3baf6))
* **mcp:** sentinel-mcp proxy subcommand runs end-to-end ([454a95c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/454a95c135968e021906da2c89ab397b23364b24))
* **mcp:** source-generated JSON context for AOT-safe argument serialisation ([69621b2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/69621b2305fdafdbdf6b8c67c5c546e2f20b14b1))
* **mcp:** StderrLogger with optional SENTINEL_MCP_LOG_JSON NDJSON output ([0daa152](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0daa152eef2318c76b765fa0966677d6dbee38af))
* **mcp:** StreamableHttp transport + SENTINEL_MCP_HTTP_HEADERS support ([12d1e71](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/12d1e711534b89c1bbd139f4e06468de53f3d214))
* **mcp:** subprocess shutdown grace period (SENTINEL_MCP_TIMEOUT_SEC, default 5s) ([4c3913e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4c3913edb091269cad1904108993bad7634c7640))
* **options:** EmbeddingGenerator + EmbeddingCache properties ([175926a](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/175926aeed309abe04a6b1682be7d8f061d4a815))
* **pipeline:** add ScanMessagesAsync for prompt-only detection ([ffbefde](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ffbefde5b3c74893d6b854863659f4d4e5374d58))
* register instrumented DetectionPipeline and AuditStore proxies in DI ([a5f65eb](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/a5f65eb7a4a93c60994af57d1a5eceae1040bc20))
* replace explicit detector registration with ZeroAlloc.Inject generated method ([22472f8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/22472f8f554f623f424fd6f967bec19868e1ab73))
* rewrite PiiLeakageDetector with 10 named patterns (US/EU/intl) ([4d763e5](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4d763e5e4f18a3e97a01fe24acf2ffdf678efccd))
* scaffold ChatApp.Client Blazor WASM project ([af961bb](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/af961bbf8e8ab748fb04b08ba311867d128f14d2))
* scaffold ChatApp.Server project ([c72a8df](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c72a8dfb35b5d0604779b432813559710cb71a50))
* scaffold ConsoleDemo project ([0a0daf3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0a0daf3e2ff0ae69a8052ac3f055de53e274a44a))
* **sdk:** AI.Sentinel.Detectors.Sdk package — SentinelContextBuilder + FakeEmbeddingGenerator ([75af48e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/75af48e214a4ea8ca26cc4a701c032720ea63907))
* **sdk:** DetectorTestBuilder assertion terminals — ExpectDetection/Exactly/Clean + cancellation ([983a816](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/983a81668cfe65cb9b31c19c5a4a63ff9b3c585a))
* **sdk:** DetectorTestBuilder generic WithDetector overloads + WithOptions ([67cbda7](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/67cbda796df9a69c09be97f9737f728fa25640dc))
* **sdk:** DetectorTestBuilder skeleton — WithDetector(IDetector) + RunAsync + pre-condition ([98b1153](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/98b1153f93fb2ce13f861c04d16442bfcef1fd2a))
* **sdk:** DetectorTestBuilder WithPrompt + WithContext (additive composition) ([8458afb](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8458afb7acdd46db7a55d59c2ef831127ed83a08))
* **sentinel:** startup warning for missing EmbeddingGenerator + OWASP LLM table in README ([ed652a3](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ed652a3dbbe91474785998ffa02b3653f45a1c84))
* **sentinel:** SystemPrefix + DefaultSystemPrefix prompt hardening ([a2dfe04](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/a2dfe04b78e17636494adca717d62735338f3ab5))


### Bug Fixes

* add branch-configure hook to UseAISentinel and static file allowlist ([50a4398](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/50a4398245d3c97884b529a85c56011ac693c0cc))
* add OnLow config, CancellationToken, extension method syntax in ConsoleDemo ([7bbc595](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7bbc595b1a7d125f893ec59548262cc3180f5263))
* address code review findings ([851d425](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/851d4251d75b7099753236e0a6f58f0692136880))
* address code review issues in sample applications ([72588a0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/72588a0257c4aab17ae663b5a37f1343aaba1d7c))
* address critical security and quality issues from code review ([51d6dd6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/51d6dd6426599fa1edd464e6eb5cbe3d779d3a3b))
* atomic AddOrUpdate in DeduplicatingAlertSink; clarify fire-and-forget discard; guard null top_detector tag; increase timing margins in test ([53e0a53](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/53e0a5304cba8c6602359ac394bf0d40ae03ee2c))
* **audit:** DisposeAsync cancels before waiting so hung inner forwarder aborts within 2s budget ([ef1c306](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ef1c3063bd1f288ba4335a2cae0538c243811170))
* **authz:** missing startup warning + doc McpProtocolException + MCP integration deny test ([7f34817](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7f34817428d63658f5dde0512d729d28c60c6c66))
* **benchmarks:** add GlobalCleanup to dispose audit store per param combination ([7537a7c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7537a7c5c45722b412ad2b1ff8d664bd27a1fb03))
* **benchmarks:** use GlobalCleanup instead of IDisposable for BDN resource disposal ([be1f841](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/be1f841b81af0f3d4808dc47c4cca5b3c5f7cc6e))
* **claudecode:** cache empty JsonElement + null-safe policy name in deny reason ([334c860](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/334c860ad409256855cf35fd01d5da67eb41a715))
* **cli:** address code review findings ([72f988c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/72f988cc9d0d17c1ddda96a842305b7f2f41792e))
* **cli:** address code review findings ([5138946](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/5138946c24ea891b4d5366d716ae9468d6159cb8))
* correct README detector counts and update design doc deviations ([916ddb7](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/916ddb746c38e99c7a0f3be4656c55d545930c18))
* correct ThreatRiskScore equality, validation guards, and aggregate signature ([4f75565](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4f75565c87989a5cc9d4b023b0a8a62d30c30523))
* **detection:** guard against zero/negative capacity in InMemoryLruEmbeddingCache ([bc79194](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/bc791949bd1ac806880ee8971d91374e2c779946))
* **detectors:** add word-boundary anchors to OPS-10 StallPattern ([943ba11](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/943ba11a99c19a91528c2bb5e52c82d08ae5935e))
* **detectors:** cap severity on LanguageSwitchAttack+ShorthandEmergence; restore injection block tests ([0b69981](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0b69981a305f6a426e7d0cb5c23d999f53f742cf))
* **detectors:** document OPS-09 / OPS-03 fence-count overlap ([037f5c0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/037f5c0f2d4efedd1de39aa122d64fdbbff0d1f9))
* **detectors:** extend SEC-21 AgencyPattern to cover 'I have deployed/spawned' ([ef9f44c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ef9f44cefec2b2a9d35747fa4b642d0dc1eca5b0))
* **detectors:** operational test assertions + benchmark factory completeness ([736df56](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/736df563074a4965b50d60570d8bca21198bd65d))
* **detectors:** OPS-09 restrict to assistant messages; OPS-11 guard promptLen==0 ([5840690](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/58406900dcd782d6ca614a54478af99d8f83c730))
* **detectors:** phantom citation LowExamples + positive-detection tests for former stubs ([38601ec](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/38601ecd9858627038bba35ee29c69af920f31ca))
* **detectors:** SEC-31 RAG-specific examples + strengthen tests ([54f44c8](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/54f44c8a1e839b711d40e720df8f406d0af6bc7f))
* **docs,detection:** update README for semantic migration + eviction guard + length safety ([07fc778](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/07fc77842e43ca59891868d45a2e0f982977c0f6))
* **docs:** add missing SEC-18 ToolDescriptionDivergence row to README security table ([af587a6](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/af587a61956db3b689034f8b10f3a2010d9e50b6))
* enforce MaxCallsPerSecond and BurstSize validation at runtime ([d08ac3a](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d08ac3a406a88f082f9990a7a55eb5be657e7e35))
* enforce PageSize in audit query; document inert validation attributes ([ef4f996](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ef4f9966e89637f65eee0a5c4c2aae8bbb902570))
* improve PublishSafe fault handling; allow IMediator injection via DI ([05575a2](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/05575a21174f2c19c753b9004c27099f15a649a4))
* log mediator publish failures; suppress notifications on PassThrough action ([34a9f7e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/34a9f7eb60287a0f1c4b2e9b3a811a0ed26a0d95))
* **mcp:** add SEC-19/21/22/30 to Security detector preset ([c1a6144](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c1a61443a905c07217ba536b572baad9ca78a133))
* **mcp:** clarify ApproximateCharLimit comment ([2c5844f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/2c5844fd82989a97d5568e6eeacf726d81fb2262))
* **mcp:** complete BuildAllDetectors (45) + add drift + mapping tests ([ffa4955](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ffa4955989a431fc3b1b96b061af683d3263808c))
* **mcp:** correct Security detector count comment (29 → 31) ([0187162](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/018716236cef19582986f991aa41c2012856be25))
* **mcp:** SENTINEL_MCP_MAX_SCAN_BYTES counts UTF-8 bytes (was char count) ([c26bc5c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c26bc5c38dd85851be3d474a2d09e5b728323f57))
* **mcp:** sync BuildAllDetectors with all 54 registered detectors ([4da4826](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/4da48262a7f961d5e7d3f527252417c2575bf687))
* **mcp:** truncate oversized request args + drop unused ProxyTargetSpec ([0da5f79](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0da5f79f621bdb2b75d96a10b7bd3eda72a3d156))
* pass materialised messageList to inner client in GetResponseAsync ([d9b19bc](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/d9b19bcea39735403323cb9a02cb9285b1011510))
* pass materialised messageList to inner client in GetStreamingResponseAsync ([c17940e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c17940e240b14d7d17c42f352675dd39774c48b4))
* remove duplicate AddAISentinel from AI.Sentinel.AspNetCore ([a98ec99](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/a98ec999b7404573cc7f0d18943f3fd2641d23b3))
* remove unused using; add within-window suppression test; clarify doc comments ([47bdcce](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/47bdcced7515737db74904c76a1e487ce174829b))
* remove user-derived content from LLM escalation system prompt ([f089c8e](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/f089c8ed1b75e546715d8bb8a341dcee4dac77a8))
* resolve 4 alert-sink bugs found in code review ([b02cdca](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/b02cdcaf9d964fc6a5b81ceb3a1a1dd59e83f6b4))
* resolve all analyzer warnings (0 warnings, 59/59 tests) ([5894e83](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/5894e839db4ed745dfe870a34f32143f61ed586d))
* scan response content through detection pipeline in SentinelChatClient ([8e8e387](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/8e8e38751cbe54e69f92e3f90e8dc88469816731))
* SentinelError.ToException() computes real ThreatRiskScore, remove misleading DetectionResult constructor ([7043d1d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/7043d1d369072430b95a32b16fbef6db0e5065e2))
* SentinelPipeline owns sentinel.scan ActivitySource span; remove [Trace] from proxy ([07e11cd](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/07e11cda631325f5746b60a70cc96703a77f3bf4))
* **sqlite:** DisposeAsync acquires write lock to avoid races with concurrent appends ([06f10aa](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/06f10aa4dd0dfd736f756e575d6f4d5726d8d19c))
* strengthen BuildSentinelPipeline test + add null guard on innerClient ([3edcd8c](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/3edcd8c8898391681793cd029082eaf03d4de031))
* **test:** correct comment in ConcurrencyAndAdversarialTests (backlog item lands in Task 8) ([5f7eb7f](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/5f7eb7f3f97d0ecafe2d2c7aad5ce21ff631cc07))
* use ex.PipelineResult in ScanAsync catch; add quarantine and failure-path tests ([c53859a](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/c53859a2ee0d9d06f7d5daafabb38cf5783597f3))
* use MaxBy(Severity) in quarantine catch block; add alert sink coverage tests ([0a823b4](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/0a823b40a97b63bbcfb18392c469e35564938221))


### Performance Improvements

* add static DetectorId/clean cache and use ctx.TextContent in 8 regex detectors ([307c003](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/307c0039cf343a391eef6ac547198b7f06b46705))
* add static DetectorId/clean cache to BlankResponse and IncompleteCodeBlock detectors ([bedd6cd](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/bedd6cdd2002c811a77651eb4690d7f1da646201))
* cache DetectorId and clean DetectionResult in StubDetector ([f59ba32](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/f59ba32136bbacd1552494bab0b57346c9eb69ab))
* convert SentinelContext to class with lazy TextContent cache ([07403f0](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/07403f06f0c4b8c2db862407d08a65b51ba931ef))
* rewrite RepetitionLoopDetector with span-based single-pass algorithm ([ac1d446](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/ac1d446541dc697eb64978513519cae39f0d6bdb))
* sync fast-path and ArrayPool in DetectionPipeline, remove LINQ aggregation ([20ceb6d](https://github.com/MarcelRoozekrans/AI.Sentinel/commit/20ceb6de939df8bd24eee467faa88c46d839dc27))

## [Unreleased]

### Highlights

- **Per-pipeline configuration (Phase A).** `services.AddAISentinel("name", opts => ...)` and `.UseAISentinel("name")` register multiple isolated pipelines under string names. Audit infrastructure stays shared; per-name detector tuning rides on `Configure<T>`.
- **Fluent per-detector config.** `opts.Configure<T>(c => ...)` disables a detector or clamps its severity output (Floor/Cap). Pipeline-level concern, no detector code changes.
- **`AI.Sentinel.Detectors.Sdk` v1.1 — `DetectorTestBuilder`.** Fluent assertion helper for unit-testing custom detectors: `WithDetector<T>().WithPrompt(...).ExpectDetection(Severity.High)`.
- **`AI.Sentinel.Detectors.Sdk` v1.0 — primitives.** `SentinelContextBuilder` + `FakeEmbeddingGenerator` for testing custom detectors offline.
- **MCP proxy (`AI.Sentinel.Mcp` + `AI.Sentinel.Mcp.Cli`).** Stdio MCP proxy that scans `tools/call` and `prompts/get` for any MCP-speaking host (Cursor, Continue, Cline, Windsurf, Copilot).
- **Audit forwarders.** `NdjsonFileAuditForwarder`, `AzureSentinelAuditForwarder`, `OpenTelemetryAuditForwarder` ship in their respective packages, with `BufferingAuditForwarder` for backpressure control.
- **Persistent audit store.** `AI.Sentinel.Sqlite` adds `SqliteAuditStore` with hash-chain integrity and time-based retention.
- **Native hook adapters.** `AI.Sentinel.ClaudeCode` and `AI.Sentinel.Copilot` (with their `.Cli` companions) wire into Claude Code's `settings.json` hooks and GitHub Copilot's `hooks.json` to scan UserPromptSubmit, PreToolUse, PostToolUse.
- **Custom detector support.** `opts.AddDetector<T>()` registers third-party detectors alongside the 51 built-in ones.

This is the pre-1.0 development history. Future entries are generated per release.

## [0.1.0] - Initial development

Initial pre-release. See git history (`git log v0.1.0..HEAD`) for the full set of commits.
