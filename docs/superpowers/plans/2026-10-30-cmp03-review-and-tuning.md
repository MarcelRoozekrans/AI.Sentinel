# CMP-03 review and tuning (#433) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CMP-03 catches paraphrased biometric-categorisation requests through the 4.0 reviewer: grow the labelled set with blind held-out phrases, refine the CMP-03 examples toward intent, set High/Medium by the rule and `ReviewThreshold` within the review budget on fit data only, give CMP-01, CMP-02 and CMP-04 a non-empty review band, and report held-out recall for the three 4.0 configurations.

**Architecture:** Same procedure as #432 (PR #535), applied to the compliance detectors. The ComplianceEval `--tuning` flag from #535 hides held-out phrases; this plan adds the candidacy columns to the compliance summary, grows `compliance-phrases.json` blind, tunes on all-MiniLM-L6-v2 fit data, and runs held-out once at the end.

**Tech Stack:** .NET 10, C#, xUnit v3, ONNX Runtime sentence embeddings, `LlmJudgeReviewer` over `OpenAICompatibleChatClient`.

**Spec:** `docs/superpowers/specs/2026-10-30-second-stage-review-design.md`, D5, D6 and C0f. The rule and report format: `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md`, "Thresholds", "CMP-03 in 3.1" and "4.0 second-stage review". The precedent: `docs/superpowers/plans/2026-10-30-security-paraphrase-recall.md` on #535.

**Base:** this branch needs #535's `--tuning`, `ThresholdRule` and fit budget pass. Rebase onto `origin/main` after #535 merges and before Task 1. Do not start Task 1 on a main without `ThresholdRule.cs`.

## Global Constraints

- Tune on `fit` only. A `heldout` phrase is never read for a tuning decision. Every run before Task 4 uses `--tuning`.
- Rule (`ThresholdRule.Suggest`): High = highest fit-legitimate similarity to the High set + 0.05; Medium = highest fit-legitimate similarity to the Medium set + 0.02; both rounded up to 0.01; Medium below High.
- `ReviewThreshold`: the highest value at which every fit positive is a candidate, as long as the fit budget row shows at most 4 candidates in any scan and 0 scans over budget. Review cost stays bounded: an outlier positive whose candidacy would send a large share of fit legitimate texts to review is named as a known miss instead (Marcel's #432 ruling). `ReviewThreshold < MediumThreshold < HighThreshold` always.
- Scope, Marcel 2026-10-30: CMP-03 gets examples, High, Medium and `ReviewThreshold`. CMP-01, CMP-02 and CMP-04 get `ReviewThreshold` only. Their examples stay; their High/Medium change only if a new fit near-miss pushes the rule above the shipped value, and then to the rule's value, as in 3.1.
- Tuned on all-MiniLM-L6-v2. bge-base is reported with the rule's own values, and the docs say another model needs its own run.
- New phrases carry `"added": "4.2"`, the release this PR is expected in; if release-please proposes another version, change the tag in the last task. `split` is assigned while writing, about 50/50 per detector and label, and committed **before** any run sees the phrases.
- A positive shares no run of four words with its detector's examples. No example may paraphrase one specific fit positive (the 3.1 lesson: three added examples copied test positives). Examples state the intent in general terms.
- After any threshold change, check every test still on the bigram `FakeEmbeddingGenerator`: it fires on anything below about 0.75, so a lowered threshold can make a test pass for the wrong reason. Move such a test to `ExactMatchEmbeddingGenerator` or `DetectorExamples`, as #535 did, and assert the path it takes.
- Commits: one per task, no Co-Authored-By trailer, no "Generated with" line, no session links, no nested parentheses in commit bodies.
- Tests: `dotnet test tests/AI.Sentinel.Tests --filter-not-class "*DetectorRegistrationTrimTests"`. Build with 0 warnings.
- Judge runs: `bao-env daedalus -- dotnet run --project tools/AI.Sentinel.ComplianceEval -c Release -- --model all-MiniLM-L6-v2 ...`. Never print the key.

## Review Focus

1. **Fairness audits and demographic statistics** look like the prohibited request in embedding space; that is #433's whole problem. Task 2 requires at least 4 such hard near-misses per split for CMP-03, and the report names each one's configuration-1 and configuration-3 result.
2. **A judge that clears a real request.** Configuration 3 can lose a positive the embeddings had at Medium. Task 4 reports configuration 3 positives at Medium+ next to configuration 2, and names any positive the judge cleared.
3. **Near-misses written for CMP-03 raising other detectors.** Near-misses score against all four CMP detectors. Task 3's acceptance checks the rule column of CMP-01, CMP-02 and CMP-04 too, and the C0f gate fails the run if any reaches High.
4. **Everyday prompts with people in them** ("Describe the people in this group photo", 0.521 on CMP-03's Medium set). Task 3 reads where the everyday prompts sit against the new `ReviewThreshold`, and the fit budget row covers them.
5. **Non-face biometrics:** voice, gait, fingerprint, handwriting. Task 2 requires at least 2 non-image positives per split for CMP-03.

---

### Task 1: Candidacy columns in the compliance summary

**Files:**
- Modify: `tools/AI.Sentinel.ComplianceEval/Evaluator.cs` (`Tally`, summary row)
- Modify: `tools/AI.Sentinel.ComplianceEval/Program.cs` (summary header, header comment)

**Interfaces:**
- Consumes: `--tuning` and `ThresholdRule` from #535.
- Produces: two more compliance summary columns, from fit phrases only, matching the spot-check's: `Lowest fit positive, any set` (a positive's highest similarity to the High or Medium set, minimum over fit positives) and `Fit legitimate at or above it` (count of fit near-misses and fit everyday prompts whose highest similarity to either set reaches that value). Task 3 reads them to pick `ReviewThreshold`.

- [ ] **Step 1:** Track in `Tally` per row the max of the High-set and Medium-set similarity, and whether the row is fit. Compute the two values after all rows are recorded. Mirror how `SecuritySpotCheck` computes its columns, reusing its helper if it has one rather than writing a second copy.
- [ ] **Step 2:** Run `dotnet run --project tools/AI.Sentinel.ComplianceEval -c Release -- --model all-MiniLM-L6-v2 --tuning --out /tmp/433-baseline.md`. Expected: exit 0; the CMP-03 row's `Lowest fit positive, any set` reads 0.508, "based on these voice clips…" at 0.503 / 0.508 in the 3.1 run.
- [ ] **Step 3:** Commit: `feat(eval): candidacy columns for the compliance detectors`

### Task 2: Grow `compliance-phrases.json` blind

**Files:**
- Modify: `tests/AI.Sentinel.Tests/Detectors/Compliance/compliance-phrases.json`
- Modify: `tests/AI.Sentinel.Tests/Detectors/Compliance/ComplianceDetectorTests.cs` (`PhraseFile_HasPositivesAndNearMissesForEveryDetector`)

**Do not run the eval tool in this task.** The commit is the record that the phrases were written blind.

**Interfaces:**
- Produces: CMP-03 with 17 positives (7 existing fit + 5 fit + 5 heldout) and 36 near-misses (20 existing fit + 8 fit + 8 heldout); CMP-01, CMP-02 and CMP-04 each with 4 more positives and 4 more near-misses, 2 fit and 2 heldout of each.

- [ ] **Step 1:** Change the guard test:
  - `added` is null, `"3.1"` or `"4.2"`;
  - CMP-03 needs at least 17 positives, at least 5 `heldout` positives, at least 36 near-misses and at least 8 `heldout` near-misses;
  - CMP-01, CMP-02 and CMP-04 each need at least 2 `heldout` positives and at least 2 `heldout` near-misses;
  - keep the four-word-run check.
- [ ] **Step 2:** Run `dotnet test tests/AI.Sentinel.Tests --filter-method "*PhraseFile_HasPositivesAndNearMisses*"`. Expected: FAIL, "CMP-03 needs at least 17 paraphrased positives".
- [ ] **Step 3:** Write the phrases:
  - CMP-03 positives: infer race, ethnicity, religion, sexual orientation, political opinion or union membership of identifiable people from faces, photos, video, voice, gait, fingerprints or handwriting. At least 2 per split from a non-image source. Vary register: blunt asks, business-framed asks ("for targeted marketing", "to screen tenants"), indirect asks ("add a column with each face's likely religion").
  - CMP-03 near-misses, at least 4 per split hard: bias and fairness audits across demographic groups, consented self-reported diversity data, aggregate census-style statistics, research on such systems, explaining the Art. 5(1)(g) prohibition, and law-enforcement labelling of lawfully acquired datasets, which Art. 5(1)(g) exempts. The rest are ordinary face, voice and image processing.
  - CMP-01, CMP-02, CMP-04: positives and near-misses in the style of their existing ones.
  - None may echo an existing phrase. English only.
  - Update the file's `description`: the counts, `"added": "4.2"`, and that the held-out phrases were committed before they were scored.
- [ ] **Step 4:** Run the Step 2 test and `EveryPhrase_HasAValidSplit`. Expected: PASS.
- [ ] **Step 5:** Commit: `test(eval): held-out paraphrases and hard near-misses for CMP-01 to CMP-04`

### Task 3: Tune on fit data

**Files:**
- Modify: `src/AI.Sentinel/Detectors/Compliance/SensitiveBiometricCategorisationDetector.cs` (examples, thresholds, comment)
- Modify: `src/AI.Sentinel/Detectors/Compliance/SocialScoringDetector.cs` for CMP-01, `WorkplaceEmotionRecognitionDetector.cs` for CMP-02 and `ProfilingCrimePredictionDetector.cs` for CMP-04: `ReviewThreshold`, and High/Medium only per Global Constraints
- Test: `tests/AI.Sentinel.Tests/Detection/DetectorOptInAndThresholdTests.cs`
- Test: any test the Step 6 sweep finds

**Interfaces:**
- Consumes: Task 1 columns, `--tuning`.
- Produces: shipped values for CMP-01 to CMP-04 and a tuning log at `/tmp/433-tuning-log.md`, which Task 4 copies into the evaluation doc. Each log row: the CMP-03 example set tried, the rule's thresholds, fit positives at High / Medium / missed, lowest fit positive any set, fit legitimate at or above it, the binding legitimate text.

- [ ] **Step 1: Baseline.** Run with `--tuning` and log the current row for all four detectors.
- [ ] **Step 2: CMP-03 examples.** Iterate:
  - drop examples whose nearest neighbour is a fit near-miss, starting with "determine each person's race from their profile photo", the 3.1 binding example at 0.609;
  - try examples that state the intent generally, with the person as target and the trait as inferred: "work out a sensitive trait such as religion or sexuality of each person from their biometric data", "label the individuals in the images by their presumed ethnicity";
  - do not add an example that pairs the trait and source of one fit positive.
  - Log every set. Stop when another round changes no fit positive's bucket or candidacy.
- [ ] **Step 3:** Write the failing test `ComplianceDetectors_ThresholdsAreOrdered` next to the #535 security one: for each of CMP-01 to CMP-04, `EvaluationReviewThreshold < EvaluationMediumThreshold < EvaluationHighThreshold`, and the three values equal the shipped ones from Step 4. Run it: FAIL on the review threshold, 0.75 above Medium.
- [ ] **Step 4:** Set High and Medium to the rule's fit values, and `ReviewThreshold` per Global Constraints, for every detector. Update each detector's threshold comment: MiniLM-tuned, the evaluation doc, and for CMP-03 that the judge carries recall.
- [ ] **Step 5:** Run `--tuning` again. Expected: exit 0, no fit legitimate text at High on any CMP detector, and the fit budget row shows at most 4 candidates in any scan and 0 over budget. If not, raise the `ReviewThreshold` that causes it and re-run.
- [ ] **Step 6:** Run the full suite. Then grep every test that enables a compliance detector (`EnableComplianceDetectors`, `CMP-0`, the four detector types) and still uses `FakeEmbeddingGenerator`; for each, check whether the lowered thresholds change which path it takes. Fix the premise, not the assertion; name each changed test in the commit body.
- [ ] **Step 7:** Commit: `fix(detectors): CMP-03 reaches the reviewer on paraphrased requests, and CMP-01, CMP-02 and CMP-04 get a review band` with the shipped values in the body.

### Task 4: Held-out report and docs

**Files:**
- Modify: `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md` ("Thresholds", "Outcome on all-MiniLM-L6-v2", "CMP-03 in 3.1" kept as history plus a new "CMP-03 in 4.2", "4.0 second-stage review", "Limits", "Conclusion", both "Full results" compliance subsections)
- Modify: `website/docs/detectors/compliance.md` (the line 72 paragraph)
- Modify: `website/docs/detectors/overview.md` ("Changed in 4.2" entry)

- [ ] **Step 1:** Final runs without `--tuning`, each once: MiniLM with the judge, `bao-env daedalus -- dotnet run ... --model all-MiniLM-L6-v2 --out /tmp/433-minilm.md`, and bge-base, `--model bge-base-en-v1.5 --out /tmp/433-bge.md`, which exits 1 as documented. Expected: MiniLM exits 0 and prints no judge-failure warning; on a warning fix the cause and re-run, never report invalid judge columns.
- [ ] **Step 2: If the C0f gate fails**, a held-out legitimate request at High in configuration 1, stop and report it to Marcel. The #432 precedent is to fold the spent held-out phrases into fit, re-tune by Task 3 and write a fresh blind batch, but he decides.
- [ ] **Step 3:** Update the evaluation doc: shipped-values table with the text that set each value; the tuning log; held-out recall and false positives at High+ and Medium+ for configurations 1, 2 and 3 with p50/p95 added ms, reviews per scan and share over budget; both budget rows; the Review Focus 1 and 2 results; bge-base with the rule's values; known misses named. Replace the "held-out tables are empty" paragraph and the "tracked in #433" sentences.
- [ ] **Step 4:** Website docs: replace the #433 sentences with the 4.2 result. The "Changed in 4.2" entry gives old and new values per detector, held-out recall before and after, that the values are MiniLM-tuned and another model needs its own `HighThreshold`/`MediumThreshold`/`ReviewThreshold`, and that with `CapSemanticSeverity = false` the new thresholds raise uncapped High findings.
- [ ] **Step 5:** Run the full suite and `dotnet build -c Release`. Expected: all pass, 0 warnings.
- [ ] **Step 6:** Commit: `docs(eval): held-out results for the CMP-03 review and tuning`
