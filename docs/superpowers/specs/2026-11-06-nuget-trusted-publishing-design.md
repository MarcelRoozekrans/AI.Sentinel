# NuGet trusted publishing for the release workflow

## Intent

The release workflow pushes to nuget.org with a long-lived `NUGET_API_KEY` secret. The key expired, and the 5.1.1 and 5.1.2 publishes both failed with a 403, so neither version is on NuGet although both are tagged on GitHub. A long-lived key will expire or leak again. Trusted publishing replaces it: the job proves who it is with its GitHub OIDC token and `NuGet/login` swaps that for an API key that lasts about an hour.

## Goals

- No long-lived NuGet credential in the repo. Every `--api-key` reads a short-lived key from a login step.
- 5.1.1 and 5.1.2 can be published from the corrected workflow without a new release.
- The second push stage cannot fail because the 30 minute indexing wait outlived the first key.

## Non-goals

- No change to what is built, packed or attested, or to the order of the push stages.
- No reusable-workflow refactor. The trusted-publishing policy names a workflow file, so the publish job stays in `release-please.yml` where the policy will point.
- Revoking the old key and deleting the secret is the maintainer's step, listed below. A workflow cannot do either.

## Approaches

1. **Inline `NuGet/login`, plus a `workflow_dispatch` republish path in the same workflow.** Chosen. One workflow file for the policy, and the dispatch path is reusable for any later failed publish.
2. Renew the key once and re-run. Rejected: keeps the mechanism that failed, and a re-run reuses the old workflow file anyway.
3. Move publish into a reusable workflow. Rejected: the policy would have to match the caller or the called file, and getting that wrong fails the first real release.

## Design

`.github/workflows/release-please.yml`
- Trigger: add `workflow_dispatch` with a required string input `version` such as `5.1.2`. The tag is `v` plus the version.
- `release-please` job: runs on `push` only.
- `native` and `publish` run when release-please created a release, or on dispatch. They use `!cancelled()` so the skipped release-please job does not skip them, and they compare `release_created` to the string `'true'`. Both check out the tag on dispatch, and a dispatch from any ref other than `main` is rejected, so the workflow file that runs is always `main`'s.
- `VERSION` is `needs.release-please.outputs.version || inputs.version`, and `TAG` is `needs.release-please.outputs.tag_name || format('v{0}', inputs.version)`. The GitHub release upload and the SBOM step use `TAG`.
- Two `NuGet/login@v1` steps with `user: ${{ vars.NUGET_USER }}`, one right before the RID push and one right before the library and pointer push, each with its own step id. Each `--api-key` reads that step's `NUGET_API_KEY` output. `secrets.NUGET_API_KEY` is gone from the file.
- `--skip-duplicate` stays, so a dispatch over a partly published version completes it.

`.github/workflows/native-cli.yml`
- Optional input `ref`, default empty, passed to its `actions/checkout`. The PR check passes nothing and is unchanged.

## Maintainer steps, outside the repo

1. On nuget.org, add a trusted publishing policy for the package owner: repository `MarcelRoozekrans/AI.Sentinel`, workflow file `release-please.yml`, no environment.
2. Add the repo variable `NUGET_USER`, the nuget.org profile name. Not the email, and not a secret.
3. After the PR merges, run the workflow with `version` 5.1.1, then 5.1.2.
4. Delete the `NUGET_API_KEY` repo secret and revoke the key on nuget.org.

## Risk

The first real run is the dispatch, so a wrong policy shows up there and not in a release. The policy covers packages the owner already owns. The RID packages first shipped with 5.0.0, so no package ID in 5.1.1 or 5.1.2 should be new; if the dispatch finds one, it fails on that package and the maintainer decides.

## Left to the builder

The exact `if:` expressions, and a short comment in the workflow naming the policy it relies on.
