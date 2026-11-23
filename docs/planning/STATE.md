# State: milestone "Controlled from a central server"

Updated 2026-11-22, late evening. Branch `docs/plan-central-server-milestone`, draft PR #668.

## Current Position

Milestone 1 holds #633, #654 to #656, #658 to #666 and #669 to #675 (20 issues). All were written or rewritten on 2026-11-22 against the approved design page. #653 and #657 are closed; each has a comment saying its decisions are replaced and what changed. Several organisations on one PC is #676, outside the milestone.

Done this session (2026-11-22, late evening):
- New issues, filed in dependency order: #669 tool kinds and shell parser, #670 five outcomes, #671 signed profile, #672 admin audit log, #673 fail mode, #674 roles per node, #675 visibility per team.
- Rewrote #633 and #654 to #666, with new titles where the scope changed (#654, #655, #656, #658, #659, #660, #661, #664).
- Spec Tasks list in Outline replaced with the 20 issues in dependency order; the "being reworked" note is gone.
- Decisions synced to Outline: ADR-247 gained the approval-request dataset (redacted input, 30 days); the Spec's settled open questions are marked; the design page has an Issues section mapping each part to its issue.
- Plans in `docs/superpowers/plans/2026-11-22-*.md` regenerated, one per issue, with the same `## Checks` layout. Old plans whose slug changed were deleted. Plans no longer say to use superpowers: build sessions do not.

Dependency order: #633, #669, #670, #671, #672 (no dependencies) then #654, #655, #658, #673, #656, #659, #664, #674, #660, #675, #661, #662, #663, #665, #666. Each issue body names its own dependencies.

Still held:
- PR #668 is ready for review; merge before a run.
- The local queue file is `.claude/unattended-queue.json.hold` in the main checkout. Do not run the unattended queue.

## Decisions (Marcel, 2026-11-22)

- The accepted ADRs win over the morning design.
- Standalone server part reads policy from a folder on disk (git checkout or Themis.NET fills it). No policy over HTTP: #664 changes.
- Refresh token: OS keychain; where none exists, memory only in the resident process. Never a plain file.
- Local Rego folder (`SENTINEL_HOOK_POLICY_DIR`) stays for PCs without a server; with a server it is combined strictest-wins.
- One server per PC in this milestone; several organisations is a follow-up issue (outside milestone 1).
- Earlier today, still standing: strictest-wins; 50 ms budget; #633 measures cold, cached-precompiled and warm on Windows, Linux, macOS in a CI matrix; hooks never send, the resident process forwards; OIDC device code; additive optional off-by-default API counts as approved; the run reads the Spec through the Outline connector.

## Open Decisions

None. Approval requests carrying the redacted tool input, deleted 30 days after decision, confirmed by Marcel on 2026-11-22; the design page and #662 say so.

## Blockers

None.

## Recommended Next Step

Ready-check done on 2026-11-22: all 20 items pass; the build check passes on main at fcfe19d. Bases follow each item's latest direct dependency (Marcel). The queue is written to `.claude/unattended-queue.json.hold` in the main checkout, still held. PR #668 is marked ready.

1. Merge PR #668 so the plans are on main before any run.
2. When Marcel wants the run: rename the queue file to `.claude/unattended-queue.json` and start it with the command below. Not before he says so.

```bash
SUPERPOWERS_UNATTENDED=1 claude -p "Run the unattended queue: build milestone 'Controlled from a central server' in AI.Sentinel, issues #633 to #675 in queue order"
```

## Inputs

- Design page (approved): Outline `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91`.
- Spec: Outline `6888019f-3202-4ea3-93a7-213cc8811bf0`.
- ADRs in the Outline Decisions collection: ADR-004, 005, 007, 008, 025, 028, 107, 108, 109, 229 to 237, 239, 240, 241, 246, 247, 249, 258. ADR-258 is only proposed. Highest number seen: 259.
- Existing code to build on: `src/AI.Sentinel/Audit/AuditHashChain.cs`, `AuditChainVerification.cs` (hash chain exists), `LocalAudit.cs` in the hook CLIs (local SQLite audit).
