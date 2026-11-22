# State: milestone "Controlled from a central server"

Updated 2026-11-22, late evening. Branch `docs/plan-central-server-milestone`, draft PR #668.

## Current Position

Milestone 1 holds #633, #654 to #656, #658 to #666 and #669 to #675 (20 issues). All were written or rewritten on 2026-11-22 against the approved design page. #653 and #657 are closed; each has a comment saying its decisions are replaced and what changed. Several organisations on one PC is #676, outside the milestone.

Done this session (2026-11-22, late evening):
- New issues, filed in dependency order: #669 tool kinds and shell parser, #670 five outcomes, #671 signed profile, #672 admin audit log, #673 fail mode, #674 roles per node, #675 visibility per team.
- Rewrote #633 and #654 to #666, with new titles where the scope changed (#654, #655, #656, #658, #659, #660, #661, #664).
- Spec Tasks list in Outline replaced with the 20 issues in dependency order; the "being reworked" note is gone.
- Plans in `docs/superpowers/plans/2026-11-22-*.md` regenerated, one per issue, with the same `## Checks` layout. Old plans whose slug changed were deleted. Plans no longer say to use superpowers: build sessions do not.

Dependency order: #633, #669, #670, #671, #672 (no dependencies) then #654, #655, #658, #673, #656, #659, #664, #674, #660, #675, #661, #662, #663, #665, #666. Each issue body names its own dependencies.

Still held:
- PR #668 is a draft. Mark it ready only after ready-check.
- The local queue file is `.claude/unattended-queue.json.hold` in the main checkout. Do not run the unattended queue.

## Decisions (Marcel, 2026-11-22)

- The accepted ADRs win over the morning design.
- Standalone server part reads policy from a folder on disk (git checkout or Themis.NET fills it). No policy over HTTP: #664 changes.
- Refresh token: OS keychain; where none exists, memory only in the resident process. Never a plain file.
- Local Rego folder (`SENTINEL_HOOK_POLICY_DIR`) stays for PCs without a server; with a server it is combined strictest-wins.
- One server per PC in this milestone; several organisations is a follow-up issue (outside milestone 1).
- Earlier today, still standing: strictest-wins; 50 ms budget; #633 measures cold, cached-precompiled and warm on Windows, Linux, macOS in a CI matrix; hooks never send, the resident process forwards; OIDC device code; additive optional off-by-default API counts as approved; the run reads the Spec through the Outline connector.

## Open Decisions

- Approval requests carry the redacted tool input and are deleted 30 days after decision. This is marked on the design page as not yet confirmed by Marcel. Ask him when he reviews the page; it does not block writing issues.

## Blockers

None.

## Recommended Next Step

1. Run the ready-check skill over the 20 milestone issues and their plans, ask Marcel for the bases, write the queue, mark PR #668 ready.
2. Ask Marcel to confirm the approval-request content and retention (Open Decisions); #662 carries it as an open question.

## Inputs

- Design page (approved): Outline `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91`.
- Spec: Outline `6888019f-3202-4ea3-93a7-213cc8811bf0`.
- ADRs in the Outline Decisions collection: ADR-004, 005, 007, 008, 025, 028, 107, 108, 109, 229 to 237, 239, 240, 241, 246, 247, 249, 258. ADR-258 is only proposed. Highest number seen: 259.
- Existing code to build on: `src/AI.Sentinel/Audit/AuditHashChain.cs`, `AuditChainVerification.cs` (hash chain exists), `LocalAudit.cs` in the hook CLIs (local SQLite audit).
