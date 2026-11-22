# State: milestone "Controlled from a central server"

Updated 2026-11-22. Branch `docs/plan-central-server-milestone`, draft PR #668.

## Position

Milestone 1 holds #633 and #654 to #666; #653 and #657 are closed with decisions in their closing comments. The plans in `docs/superpowers/plans/2026-11-22-*.md` and those decisions follow a design that conflicts with accepted ADRs. Marcel decided: **the ADRs win**. Rework everything before any unattended run.

Held until the rework is done:
- PR #668 is a draft. Do not merge it as it stands.
- The local queue file is renamed to `.claude/unattended-queue.json.hold` in the main checkout.
- The Outline design page "AI.Sentinel: central server control, design" (id `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91`) says "under rework".

## Inputs

- Spec: Outline `6888019f-3202-4ea3-93a7-213cc8811bf0`, "AI.Sentinel: be controlled from Themis.NET". It predates most of the ADRs below.
- ADRs in the Outline Decisions collection; read each one in full before writing: ADR-004, 005, 007, 025, 028, 107, 108, 109, 229 to 237, 239, 240, 241, 247, 249, 258. Highest number seen: 259.
- Decisions Marcel made today that still stand unless an ADR overrides them:
  - Policy combination is strictest-wins; this matches ADR-108 and ADR-232.
  - Evaluation time budget is 50 ms per call, from ADR-007.
  - #633 must measure cold, cached-precompiled and warm evaluation and prove Windows, Linux and macOS in a CI matrix.
  - The hooks never send to the server themselves; a forwarder in the local process does. This matches ADR-231 and ADR-004.
  - OIDC device code for sign-in, matching ADR-005.
  - Additive, optional, off-by-default public API that the Spec asks for counts as approved.
  - The unattended run reads the Spec through the Outline connector.

## Conflicts found (subagent check, 2026-11-22)

- **ADR-236:** The server compiles all bundles into one module named in the signed profile. A resident evaluator answers first, with fallback to in-process evaluation and then to the server. Outside-reaching builtins are refused at validation and denied at runtime with a named reason. Each decision records where it was made. This replaces "the hook evaluates" and the separate org and team evaluation in #656 and the design.
- **ADR-233:** The profile is signed with Ed25519, and its keys are pinned at sign-in. The organisation and repository must match. The profile expires after 7 days, and an edited cache is unusable. After expiry the ADR-237 fail mode applies. The "last known policy in a plain state file" in #658 and #664 is the threat this ADR closes.
- **ADR-237:** `fail_mode` per node is `closed` by default, or `ask`. Read-only tools inside the repo stay allowed in both modes. A bundle error at runtime always denies and names the bundle. The milestone also needs a defined state for "server configured, no profile yet".
- **ADR-234:** Outcomes are deny, ask, guidance, allow and defer. Allow never overrides the CLI's own permission prompt. Where a CLI cannot ask, ask becomes deny. Every decision carries a reason, the policies involved and the policy version. Guidance is in scope.
- **ADR-235:** Policies use shared tool kinds: shell, read, search, write, edit, fetch, mcp, agent and other. An unparseable shell command gets ask, which becomes deny where nobody can answer. The design's input `tool: { name, args }` is wrong.
- **ADR-240:** The decision log is pseudonymous and never stores the command. Reason text is stored only with detailed logging, and then redacted. #660 and #661 store and send everything as it arrives.
- **ADR-241:** The audit log is append-only and hash-chained per organisation, with an offline verify command. Every admin action is logged with its channel: publish, approval, rollback, pause.
- **ADR-239:** Activity is shown per team without names by default. Names need an approval reference, and the minimum team view is 3 people. A team lead can pause an unnamed developer.
- **ADR-247:** Telemetry follows a field allowlist, with per-organisation pseudonyms. Retention is 30 days for the session view, 90 days for events and 13 months for counts.
- **ADR-109:** There are three roles from IdP groups. A team lead acts only on their own team. This scoping is missing from #662 and #663, and #664 maps groups to teams but not to roles.
- **ADR-004 and ADR-107:** Policy lives only in git. #664 "accept policy over HTTP" conflicts with this. A standalone team without Themis.NET still needs some way to deliver policy; ask Marcel.
- **ADR-230:** No stored secrets. #659 stores the refresh token in a plain file; consider the OS keychain.
- **ADR-028:** Hook CLIs ship per RID with SHA256SUMS and attestation. #665 packaging must match.
- **ADR-258:** This ADR is only proposed. It says no Codex adapter exists, so #665 makes its premise stale.

## Next steps

1. Rewrite the Outline design page to follow the ADRs; set it to approved only after Marcel confirms the open choices. Ask Marcel only where an ADR leaves a real choice, such as ADR-004 versus standalone policy delivery, or refresh token storage.
2. Update the Spec in Outline: Scope and Open questions point to the ADRs and the design. Also update the ADRs themselves where the outcome of #633 is meant to be added (ADR-236) or a point is superseded.
3. Rewrite #653 and #657 decisions as follow-up comments; update #633, #654 to #666, and add issues for uncovered ADR requirements: signed profile, fail mode, tool kinds and outcomes, decision-log privacy, append-only audit and admin-action logging, role scoping, visibility per team. One issue per PR, in the milestone, in dependency order.
4. Regenerate the plans on this branch, with the same Checks layout. The generator was a throwaway script; rewrite them. Run the ready-check skill, ask Marcel for bases, write the queue, mark PR #668 ready.
