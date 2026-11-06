# NuGet trusted publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The release workflow pushes to NuGet with short-lived trusted-publishing keys, and a manual dispatch can publish an existing tag.

**Architecture:** `NuGet/login@v1` runs inline in the publish job before each push stage. `workflow_dispatch` with a `version` input runs native and publish against the tag, with the release-please job skipped.

**Tech Stack:** GitHub Actions YAML.

**Spec:** `docs/superpowers/specs/2026-11-06-nuget-trusted-publishing-design.md`

## Global Constraints

- No `secrets.NUGET_API_KEY` anywhere in `.github/`.
- The publish job stays in `release-please.yml`. Two `NuGet/login@v1` steps with `user: ${{ vars.NUGET_USER }}`, ids `nuget-login-rid` and `nuget-login-libs`.
- Dispatch input `version`, required string such as `5.1.2`; tag is `v` plus version; dispatch from a ref other than `main` is rejected.
- `native-cli.yml` gains optional input `ref`, default empty; the PR check is unchanged.
- Commit type `ci:`. No nested parentheses in commit bodies, no Claude signature or session link.

## Review Focus

- A push to main that creates no release still skips native and publish.
- A dispatch with release-please skipped still runs native and publish, and uses the tag's code.
- The upload to the GitHub release and the SBOM step name the right tag on both paths.

---

### Task 1: Trusted publishing and the dispatch path

**Files:**
- Modify: `.github/workflows/release-please.yml`
- Modify: `.github/workflows/native-cli.yml`

**Interfaces:**
- Produces: workflow_dispatch input `version`; `native-cli.yml` input `ref` (string, default `''`).

- [ ] **Step 1: native-cli.yml.** Add `ref` (string, not required, default `''`) to the `workflow_call` inputs with a description, and pass `ref: ${{ inputs.ref }}` to its `actions/checkout`.
- [ ] **Step 2: release-please.yml triggers and gating.** Add `workflow_dispatch` with the `version` input. Give `release-please` the condition `github.event_name == 'push'`. Give `native` and `publish` the condition `!cancelled() && (needs.release-please.outputs.release_created == 'true' || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'))`, and pass `native` the version `needs.release-please.outputs.version || inputs.version` and `ref` of `format('v{0}', inputs.version)` on dispatch, empty otherwise. `publish` also needs `native` to have succeeded, so it keeps `needs: [release-please, native]` and the condition adds `needs.native.result == 'success'`.
- [ ] **Step 3: publish job.** `VERSION` and a new `TAG` come from release-please outputs with the dispatch fallbacks from the spec. The checkout takes `ref` the same way as native. The upload and SBOM steps use `TAG`. Replace the three `--api-key ${{ secrets.NUGET_API_KEY }}` uses with the outputs of the two `NuGet/login@v1` steps, the second login placed after the wait step. Add a short comment naming the nuget.org policy the job relies on.
- [ ] **Step 4: Verify.** Run `grep -rn NUGET_API_KEY .github` expecting only the login outputs, validate the YAML with `python3 -c 'import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/release-please.yml .github/workflows/native-cli.yml`, and run `actionlint` if installed.
- [ ] **Step 5: Commit.** `ci(release): publish to NuGet with trusted publishing and add a republish dispatch`, body ending with Refs for the failed 5.1.1 and 5.1.2 publishes.
