# State: milestone "Controlled from a central server"

Updated 2026-11-22. Branch `docs/plan-central-server-milestone`, draft PR #668.

## Current Position

Milestone 1 holds #633 and #654 to #666; #653 and #657 are closed with decisions in their closing comments that are now out of date. The plans in `docs/superpowers/plans/2026-11-22-6*.md` follow the replaced design and must be rewritten.

Done this session (2026-11-22, evening):
- Read every ADR listed below in full, plus ADR-008 and ADR-246.
- Rewrote the Outline design page "AI.Sentinel: central server control, design" (`b4b02d34-d3a1-4141-b5a0-4d51bcba7d91`) to follow the ADRs. **Status: approved 2026-11-22.** It is now the source for issues and plans.
- Spec (`6888019f-3202-4ea3-93a7-213cc8811bf0`): added "How this Spec is built", marked answered open questions, and a "being reworked" note under Tasks. Remove that note once step 2 below is done.
- ADR additions (2026-11-22): ADR-107 (server part reads a policy folder), ADR-005 (token in OS keychain, else memory), ADR-007 (local Rego folder, additive), ADR-246 (one server per PC this milestone).

Still held:
- PR #668 is a draft. Do not merge it as it stands.
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

1. Rewrite the issues against the approved design page:
   - Add follow-up comments to closed #653 and #657 saying their decisions are replaced by the design page, with the points that changed.
   - Rewrite the bodies of #633 and #654 to #666. Key changes: #656 becomes node-from-repository (no `SENTINEL_HOOK_TEAM`); #658 becomes the signed profile cache plus pause state; #659 keychain or memory; #660 and #661 follow ADR-240 and ADR-247 field allowlist; #662 and #663 gain role-on-node checks and ADR-241 audit; #664 reads a policy folder, compiles, validates and signs, no HTTP upload; #665 per ADR-028 packaging.
   - New issues, one per PR, in the milestone, in dependency order: signed profile and key pinning (ADR-233); tool kinds and shell parser with corpus (ADR-235); five outcomes and their mapping per CLI (ADR-234); fail mode (ADR-237); append-only audit log of administrative actions with export and offline verify (ADR-241); role scoping per node (ADR-109, ADR-232); visibility per team, names setting, minimum 3 (ADR-239). File the several-organisations follow-up outside the milestone.
   - Then update the Spec's Tasks list and remove its "being reworked" note.
2. Regenerate the plans on this branch with the same `## Checks` layout; delete the old ones that no longer match an issue.
3. Run the ready-check skill, ask Marcel for bases, write the queue, mark PR #668 ready.

## Inputs

- Design page (approved): Outline `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91`.
- Spec: Outline `6888019f-3202-4ea3-93a7-213cc8811bf0`.
- ADRs in the Outline Decisions collection: ADR-004, 005, 007, 008, 025, 028, 107, 108, 109, 229 to 237, 239, 240, 241, 246, 247, 249, 258. ADR-258 is only proposed. Highest number seen: 259.
- Existing code to build on: `src/AI.Sentinel/Audit/AuditHashChain.cs`, `AuditChainVerification.cs` (hash chain exists), `LocalAudit.cs` in the hook CLIs (local SQLite audit).
