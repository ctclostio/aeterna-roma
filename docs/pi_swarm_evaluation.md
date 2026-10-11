# Pi ox-alpha swarm evaluation

This evaluation covers the supervised OpenRouter run
`out\pi-swarm\20260824-x64-wave1`. Raw prompts, Pi sessions, stdout reports,
stderr, and exit codes are retained below that ignored run directory.

## Report rubric

Each read-only engineering report is scored out of 100:

| Category | Points | Standard |
|---|---:|---|
| Evidence accuracy | 25 | Claims, counts, paths, signatures, and provenance agree with repository evidence. |
| x64/ABI reasoning | 25 | Guest/host widths, layouts, calls, exports, and uncertainty are handled safely. |
| Actionability | 15 | Proposed work is concrete, minimal, and ordered around real blockers. |
| Verification design | 15 | Tests can falsify the proposal and cover regressions and negative cases. |
| Scope and safety | 10 | Immutable artifacts and shared-worktree boundaries are respected. |
| Efficiency | 10 | The worker avoids redundant or runaway searches and minimizes supervisor intervention. |

Scores mean: 90–100 exceptional, 80–89 strong, 70–79 useful with review,
60–69 mixed/high-review, 50–59 weak, and below 50 not worth delegating in its
current form. A plausible-looking unsafe patch is graded as unsafe, regardless
of prose quality.

## Code rubric

Write-enabled follow-up work is scored separately out of 100:

| Category | Points | Standard |
|---|---:|---|
| Correctness and build | 30 | The assigned implementation builds and behaves as specified. |
| Tests and negative gates | 20 | Focused tests pass and demonstrate rejection of invalid inputs/states. |
| x64/ABI safety | 20 | No silent truncation, layout drift, invented ABI, or warning suppression. |
| Provenance and regression safety | 15 | Canonical inputs remain immutable and existing validation stays green. |
| Maintainability | 10 | Narrow interfaces, clear ownership, deterministic artifacts, readable diff. |
| Autonomy | 5 | Low supervisor correction/rework burden. |

The final usefulness verdict reports both arithmetic averages and the share of
workers at or above 70 and 80. It also records wall time, token usage, reported
provider cost, failed workers, and supervisor interventions so quality is not
separated from operating cost.

## Results

Wave one completed 20/20 workers. Independent grading checked the reports
against the immutable corpus, compiler logs, manifests, and targeted original
PE disassembly.

| Worker | Task | Score | Disposition |
|---|---|---:|---|
| w01 | TU 102df760 | 68 | Mixed; no patch handoff |
| w02 | TU 10328370 | 54 | Unsafe layout/truncation proposal |
| w03 | TU 104c76c0 | 59 | Mixed; no patch handoff |
| w04 | TU 1064d4e0 | 30 | Unsafe struct layout |
| w05 | TU 10698600 | 52 | Unsafe pointer/overflow proposal |
| w06 | TU 10802630 | 80 | Conditional guest-memory follow-up |
| w07 | TU 108a8e80 | 31 | Misread central call |
| w08 | TU 1093c450 | 67 | Correct thunk, unsafe width assumption |
| w09 | TU 109555c0 | 77 | Useful six-slot ABI evidence |
| w10 | TU 10981dd0 | 44 | PE disproved proposed behavior |
| w11 | TU 109871d0 | 47 | Overlapping widened fields |
| w12 | TU 10a132b0 | 40 | Unsafe guest-to-host casts/layout |
| w13 | TU 10c93ea0 | 79 | Conditional port-layer follow-up |
| w14 | TU 10f17100 | 73 | Useful with boundary/test corrections |
| w15 | TU 10f4f540 | 71 | Useful after arity adjudication |
| w16 | TU 10f537c0 | 48 | Unsafe low-4GB pointer policy |
| w17 | Warning triage | 72 | Strong audit; mutation plan rejected |
| w18 | Guest32 data model | 75 | Conditional test-first follow-up |
| w19 | Export integration | 80 | Best implementation candidate after factual corrections |
| w20 | Startup/dependencies | 39 | Raw-audit idea useful; design materially wrong |

Arithmetic mean: **59.3/100**. Eight workers (40%) scored at least 70, two
(10%) scored at least 80, and none scored 90. No proposed TU patch was safe to
apply verbatim.

Objective run metrics from `scripts/summarize_pi_swarm.py`:

- 20/20 successful final reports;
- 507 assistant turns and 740 tool calls;
- 7,157,709 reported total tokens, including 6,375,744 cache-read tokens and
  196,264 output tokens;
- reported provider cost: **$0.00**;
- longest worker duration: 1,213 seconds;
- seven stalled broad searches terminated by the supervisor and one preserved
  session resumed after a hung final response.

The recurring failure mode was not lack of effort. It was confident widening
of four-byte guest pointer cells into eight-byte native fields, which moved or
overlapped adjacent fields. Other material misses included silently truncating
allocator results, treating generated canonical artifacts as editable, wrong
warning/export counts, and behavior inferred from decompiled C that original PE
disassembly contradicted.

Verdict: ox-alpha is cost-effective for parallel evidence gathering and
candidate discovery at the currently reported zero provider cost. It is not
safe for unsupervised port patches. Use bounded scopes, independent PE checks,
immutable-source rules, explicit negative tests, and supervisor-owned
integration. Code quality is evaluated separately in the write-enabled wave.

## Write-enabled startup-audit bake-off

The same 20 sessions then received one exact, hash-locked implementation task.
Each worker wrote only to its own ignored candidate directory under
`out\pi-swarm\20260824-startup-code-bakeoff`. Every submission was reviewed
against the code rubric, its own tests were rerun, and an independent oracle
reconstructed all 9,874 expected rows directly from the original PE and
canonical function index.

| Worker | Report score | Code score | Code disposition |
|---|---:|---:|---|
| w01 | 68 | 73 | Exact corpus output; PE overlap and publication defects |
| w02 | 54 | 80 | Strong with PE-header/raw-boundary hardening |
| w03 | 59 | 77 | Useful; malformed-index/TOCTOU defects |
| w04 | 30 | 83 | Best parser in subset; extra artifacts and publication defect |
| w05 | 52 | 74 | Exact output; raw-EOF/index validation defects |
| w06 | 80 | 69 | Strong tests; complex state and supervisor retry |
| w07 | 31 | 68 | Exact output; missing MZ and temp-file policy defects |
| w08 | 67 | 68 | Incorrect e_lfanew width and weak raw-range validation |
| w09 | 77 | 71 | Summary reports first nonzero as first raw value |
| w10 | 44 | 82 | Exact output; missing MZ validation |
| w11 | 47 | 58 | 1,111 joined rows contain the wrong canonical-entry field |
| w12 | 40 | 71 | Exact output; PE/TOCTOU defects and extra artifacts |
| w13 | 79 | 83 | Strong tests; PE boundary and publication defects |
| w14 | 73 | 88 | Strongest PE-oriented base; publication still unsafe |
| w15 | 71 | 87 | Clean core; header and publication hardening required |
| w16 | 48 | 74 | Correct TSV; incomplete nonzero summary and two retries |
| w17 | 72 | 89 | Best overall score and tests; PE/publication hardening required |
| w18 | 75 | 81 | Exact output; index normalization/TOCTOU defects |
| w19 | 80 | 86 | Well structured; raw-overlap edge and publication defect |
| w20 | 39 | 82 | Fast exact implementation; PE/publication edge defects |

Arithmetic mean: **77.2/100**. Sixteen workers (80%) scored at least 70, ten
(50%) scored at least 80, and none scored 90. Report score was only a weak
predictor of code score (Pearson `r = 0.265`; Spearman `rho = 0.245`). In the
largest reversal, w20 rose from a 39 report to 82 code score, while w06 fell
from 80 to 69 because of implementation complexity and supervision burden.

The corrected independent oracle found 13 submissions with exact required
files and complete semantic outputs. Four more generated correct semantic
outputs but left forbidden `__pycache__` artifacts. The three substantive
output failures were w09's summary sentinel fact, w11's 1,111 corrupt joined
entry cells, and w16's missing nonzero counts. Static adversarial review then
found additional malformed-PE and malformed-index cases beyond the oracle's
real-corpus checks.

Objective write-wave metrics from `scripts/summarize_pi_startup_bakeoff.py`:

- 20/20 successful worker exits, 620 assistant turns, and 599 tool calls;
- 36,279,690 reported total tokens, including 34,136,064 cache-read tokens and
  606,368 output tokens;
- reported provider cost: **$0.00**;
- longest worker duration: 1,442 seconds;
- no detected non-temporary write outside the assigned candidate directories;
- one hung w06 turn required a preserved-session retry, and w16 required two
  retries after terminal provider-throttle responses.

The most important result is the correlated failure: all 20 implementations
staged both files and then replaced them sequentially without rollback. A
failure on the second replacement can leave a mixed old/new pair. Parallel
agreement therefore did not make the design safe. No submission is accepted
verbatim; supervisor-owned integration starts from the best parser/test work
and adds rollback, injected publication-failure tests, and the cross-candidate
PE/index negative cases.

Updated verdict: ox-alpha is worth using for tightly specified, isolated code
generation when an independent oracle and human integration review are part of
the workflow. It is not worth using as an autonomous port owner. The swarm is
most valuable as a high-throughput candidate generator; correlated mistakes
make majority agreement an unsafe substitute for an external acceptance gate.

Supervisor integration did not accept any candidate verbatim. The hardened
implementation combines the strictest parser/index behavior with independent
writable backups, rollback and recovery-evidence handling, Windows filesystem
tests, exact schema tests, and LF provenance rules. Its final suite passes
45/45 tests, and the same independent bake-off oracle reports a strict pass
with zero issues and byte-exact 9,874-row output. This is the useful operating
model for later swarms: workers propose bounded implementations; the supervisor
owns adversarial testing, correlated-defect review, and the final artifact.

## Wave-three evidence transport pilots

Wave three separates 20 roles into evidence, oracle, isolated implementation,
cross-review, and integration stages. Two four-worker evidence pilots were
stopped before downstream work because their deliverables did not pass the
supervisor gate. Failure-inclusive snapshots are retained as
`grading_snapshot.json` in both ignored run directories.

| Run | Completed/stopped | Exact schema-valid reports | Tokens | Tool calls | Disposition |
|---|---:|---:|---:|---:|---|
| `20260824-entry-policy-wave3` | 4 / 0 | 0/4 | 377,138 | 50 | Rejected; malformed transport and unverified source hashes |
| `20260824-entry-policy-wave3-r2` | 3 / 1 | 1/4 | 857,348 | 58 | Rejected; two malformed JSON reports and one live token overrun |

Combined, only one of eight attempted report transports (12.5%) was exact and
schema-valid. The second pilot's raw-provenance worker reached 621,092 reported
tokens against a 250,000-token cap before manual termination; 559,616 of those
tokens were cache reads. These attempts count as supervision cost even though
no evidence stage was accepted.

This is a negative grade for using final chat text as a structured-artifact
transport, not yet a grade of wave-three code quality: implementation workers
have not run. The next frozen run moves E/O/R deliverables into isolated,
schema-validated workspace files, adds live process-tree budget enforcement,
and lowers the remaining 20-role envelope from 7.5M to 5.5M tokens. Code will
still be graded only by supervisor-owned tests and mutants, with correctness,
code quality, diversity value, supervision cost, and verbatim acceptance
reported separately.

### Supervised r3 evidence and oracle run

Run `20260824-entry-policy-wave3-r3` exercised the workspace-artifact transport
with four evidence and four oracle workers. It is retained as a failed,
failure-inclusive run; no stage manifest was published and no downstream code
worker consumed its outputs.

| Stage | Worker outcomes | Schema-valid artifacts | Tokens | Tool calls | Mean grade |
|---|---|---:|---:|---:|---:|
| Evidence | 3 completed, 1 budget-exceeded | 4/4 | 457,097 | 46 | 75.0 |
| Oracle | 1 completed, 1 budget-exceeded, 2 peer-stopped | 3/4 | 444,628 | 36 | 66.0 |
| Combined | 4 completed, 2 budget-exceeded, 2 peer-stopped | 7/8 | 901,725 | 82 | 70.5 |

The transport improvement is real: exact schema compliance rose from 1/8 in
the two chat-text pilots to 7/8. It did not make the content self-validating.
Evidence grades were E01 66, E02 84, E03 72, and E04 78. Oracle grades were
O01 84, O02 61, O03 70, and O04 49; O04's raw work was capped because it wrote
19 mutants where the schema permits 16. Only four of eight workers completed
inside both their resource envelope and terminal-transport rules.

Central review found useful defects that the swarm itself had overstated:
`startup_slots.tsv` and `export_manifest.tsv` were parsed by provenance tests
without authenticating their bytes. It also rejected false or imprecise claims
about mismatch control flow, original call counts, startup-target identity,
historical publication defects, and bidirectional oracle mappings. The
supervisor now hash-pins both tables from a single read before parsing.

r3 also exposed two orchestration defects. PowerShell scalar unwrapping made a
valid one-file workspace appear to have three inventory entries, and a local
worker overrun aborted independent peers that had already deposited artifacts.
The r4 harness wraps inventory records explicitly, stops only the worker that
violates a worker-local cap, retains stage-wide abort for the 5.5M run ceiling,
uses stage-specific schema guidance, and asks E/O workers to write by their
eighth tool call. E/O reasoning is reduced from high to medium. The repaired
harness passes 22/22 tests before r4 launch.

### r4 cost trial and r5 semantic gate

r4 ran E and O concurrently. That was a process mistake: two watchdogs read the
same session area while Pi was writing, and E03 ended with an `EBUSY` session-log
error. E01 was then peer-stopped under the old ordinary-failure policy. O itself
completed four workers without budget overruns, but O03 misused `blockers`, O04
emitted invalid JSON (`\0`), and all four documents contained nonreciprocal
test/mutant edges.

| Metric | r3 | r4 | Delta |
|---|---:|---:|---:|
| Failure-inclusive evidence mean | 75.0 | 66.0 | -9.0 |
| Failure-inclusive oracle mean | 66.0 | 71.0 | +5.0 |
| Combined mean | 70.5 | 68.5 | -2.0 |
| Tokens | 901,725 | 609,310 | -292,415 (-32.4%) |
| Tool calls | 82 | 74 | -8 |
| Cumulative worker wall time | 2,470.199 s | 1,035.895 s | -1,434.304 s (-58.1%) |

r4 evidence scores were E01 0 (no artifact), E02 91, E03 88, and E04 85.
Oracle scores were O01 85, O02 81, O03 69, and O04 49 after the malformed-JSON
cap. The six schema-valid delivered artifacts averaged 83.17, but that selected
average is not substituted for the failure-inclusive result.

r5 therefore serialized stages and isolated ordinary worker failures while
retaining stage abort for identity mismatch and the run-wide token ceiling. Its
four E workers all completed: 295,674 tokens, 39 tool calls, four exact
schema-valid artifacts, and no transport/resource failure. Claim-level review
still rejected publication. Scores were E01 82, E02 79, E03 86, and E04 83
(mean 82.5). Defects included treating mismatch fallthrough as a displaced
branch target, predicting an unproven Candidate-A import change, compound claims
with only one cited hash, and incomplete dynamic-probe adjudication.

The r6 process makes E claims atomic and single-source, hard-codes the known
control-flow distinctions into the role charters, serializes every stage, and
enforces O as exactly eight worker-prefixed one-to-one test/mutant pairs. The
harness also rejects incomplete/duplicate I/G file inventories. These checks
pass 26/26 prelaunch tests. The main conclusion remains stable: ox-alpha is
useful enough to keep, but parallel agreement and schema compliance do not
replace semantic review.

### r6 selector implementation outcome

Run `20260824-entry-policy-wave3-r6` used
`openrouter/stealth/ox-alpha`. Evidence and oracle transport completed without
resource failures, but their raw content still required supervisor
adjudication before publication.

| Stage | Outcomes | Tokens | Tool calls | Raw mean |
|---|---|---:|---:|---:|
| Evidence | 4 completed | 245,861 | 36 | 82.5 |
| Oracle | 4 completed | 199,989 | 29 | 69.5 |
| Implementation | 1 completed, 4 budget-exceeded, 1 failed | 1,775,273 | 131 | see below |
| Attempted total | 14 workers | 2,221,123 | 196 | — |

The supervisor froze a separate x64 hidden oracle before implementation. It
compiled candidates under C17 `/W4 /WX /sdl /GS /guard:cf`, enforced token-aware
source bans, exercised exact guest/address boundaries and guard pages, and
proved three seeded mutants were rejected.

Independent implementation grades distinguish source quality from autonomous
delivery:

| Worker | Terminal result | Advisory code grade | Hidden oracle | Verbatim |
|---|---|---:|---|---|
| I01 | completed | 73 | pass | no; production only |
| I02 | budget-exceeded | 80 | pass | no |
| I03 | budget-exceeded | 81 | pass | no |
| I04 | failed (`EBUSY`) | 24 | not runnable; selector wrong | no |
| I05 | budget-exceeded | 85 | pass | no |
| I06 | budget-exceeded | 80 | pass | no |

The advisory workspace-code mean is 70.5. Five of six core implementations
passed the hidden oracle, showing strong bounded coding ability. The autonomous
package result is much worse: zero of six was acceptable verbatim, only one
worker reached normal completion, and that worker's own tests contained memory
errors and false cases. With stopped/failed workers receiving zero delivery
credit, the failure-inclusive deliverable mean is 12.2 (I01's 73 divided over
all six workers). The implementation workers averaged 295,879 tokens and 21.8
tool calls each, a high supervision cost for this small slice.

Supervisor integration therefore used I01's four minimal production files,
I05's safer test structure, independently corrected cases, the existing pinned
provenance test, and the hidden oracle. No entire worker package was promoted.
The integrated selector passes the hidden oracle and the repository's expanded
8/8 CTest suite while `empire.retail64.dll` remains byte-identical and inert.

The r6 stage remains recorded as failed; raw worker statuses were not rewritten
to unlock downstream stages. A failure-inclusive snapshot was frozen at
`out/pi-swarm/20260824-entry-policy-wave3-r6/supervisor-adjudication/grading_snapshot_after_i.json`
before integration.

The `EBUSY` incident exposed a live-session reader race. The next harness
revision reads and hashes one `FileShare.ReadWrite | FileShare.Delete` snapshot,
parses only newline-complete live records, switches to strict terminal reads,
limits snapshots to 32 MiB, rejects counter/hash regression, and permits only a
bounded live I/O grace. Its local suite passes 30/30. A small sharing canary is
required before another enforcement-grade swarm.

Overall verdict: ox-alpha is worth using for multiple isolated source proposals
and adversarial ideas under a supervisor-owned oracle. It is not yet worth
treating as an autonomous finisher; budgets, exact artifact transport, and
independent tests must remain hard gates.

### Dynamic-probe r5/r6 outcome and 20-role completion

The next wave targeted the test-only x64 DLL boundary for the entry-policy
selector with the same `openrouter/stealth/ox-alpha` model. Formal evidence and
oracle stages validated, but implementation workers again failed to stop and
package their work.

| Run | I01 | I02 | I03 | I04 | I05 | I06 | Mean Q | Median Q | Valid submissions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dynamic-probe r5 | 65 | 29 | 49 | 31 | 69 | 30 | 45.5 | 40.0 | 0/6 |
| dynamic-probe r6 | 69 | 62 | 69 | 49 | 18 | 49 | 52.7 | 55.5 | 0/6 |

All delivery scores are zero. In r6, every I worker exceeded its 650,000-token
limit before writing `submission.json`: 4,009,643 tokens and 177 tool calls in
total, or 668,274 tokens and 29.5 calls per candidate. Four of six DLL cores
passed all 13 frozen runtime groups, one failed a null-output case, and one did
not compile. This is strong evidence for donor value and equally strong
evidence against autonomous package ownership.

The best integrated result used the exact ABI/export contract from the strongest
candidates, a corrected `uint64_t` version export, the supervisor's
sensitivity-tested fixtures, a hardened independent PE parser, and a stricter
link-map gate. No candidate host, CMake package, or PE gate was adopted
verbatim. The resulting local build passes 15/15 CTest cases, including 13
real DLL-boundary groups and post-run bootstrap authentication, while the
tests-off build contains no probe artifact.

Formal R/G stages correctly remained blocked because there was no admitted I
manifest. To complete the requested 20-role experiment without falsifying the
formal state, the four reviewer and two integrator slots ran as a separately
labeled, read-only salvage wave against the frozen integration. External
telemetry, not worker self-report, enforced the stop policy.

| Worker | Advisory usefulness Q | Tokens | Calls | Outcome |
|---|---:|---:|---:|---|
| R01 ABI/memory | 84 | 12,659 | 7 | Accurate pass; completed |
| R02 host lifecycle | 72 | 81,738 | 6 | Found the unsafe timeout path; one false high-address concern |
| R03 build containment | 79 | 41,140 | 7 | Accurate pass with two low future-hardening notes |
| R04 adversarial gates | 73 | 90,807 | 8 | Useful map/export blind spots; malformed JSON delivery |
| G01 release adjudicator | 0 | 65,258 | 12 | Exceeded the 10-call cap; externally stopped; no report |
| G02 next slice/process | 73 | 59,094 | 9 | Useful process changes; missed the smaller executable leaf |

The salvage usefulness mean is 63.5 (median 73), using 350,696 tokens and 49
calls total. Five of six obeyed the externally enforced call cap. Only R01's
self-reported call count matched telemetry; exact transport remains unreliable.
Four reports became parseable after removing a Markdown fence, R04's JSON was
malformed, and G01 produced none.

This refinement reduced mean token use per role from 668,274 for r6
implementation packages to 58,449 for narrow reviews, an 11.4x reduction. The
operational policy going forward is therefore:

- give ox-alpha one function, one gate, or one review dimension at a time;
- make the supervisor own scaffolding, manifests, packaging, builds, and final
  integration;
- enforce call/token stops externally and preserve partial source snapshots;
- grade technical donor value separately from autonomous delivery;
- never promote majority agreement without original-byte provenance and an
  independent mutant-sensitive oracle.

### Startup-ABI r6 calibration

Run `20260825-startup-abi-wave3-r6` tested the new artifact checkpoint against
the `0x100edd70 -> 0x100ed3c0` boundary. It is preserved as a failed calibration
run: three evidence workers completed, E04 was stopped exactly at its tenth
completed tool result because it had performed ten reads without persisting an
artifact, and no downstream stage launched.

| Worker | Result | Technical | Operational | Tokens | Calls |
|---|---|---:|---:|---:|---:|
| E01 caller packet | completed, rejected | 86 | 74 | 53,002 | 5 |
| E02 stack reads | completed, rejected | 88 | 97 | 54,484 | 6 |
| E03 frame/return | completed, rejected | 78 | 45 | 127,391 | 7 |
| E04 leaf triage | checkpoint failure | 0 | 0 | 17,223 | 10 |

The three delivered artifacts average 84.0 technically. Counting the missing
E04 as zero gives a failure-inclusive technical mean of 63.0 and operational
mean of 54.0. Total use was 252,100 tokens and 28 completed tool results. No
explicit HTTP 429 or rate-limit record occurred; E03 instead experienced one
long upstream-latency interval and then resumed.

The run was still valuable because the supervisor rejected plausible-looking
content. E01 missed an exact semantic token and contradicted itself about what
was conditional in ESI/EDI provenance. E02 misstated the canonical return
declaration and overstated its coverage of small ESP-relative locals. E03
bundled caller-use, return-value, and termination facts under one callee source,
used a forbidden convention-style inference, claimed all three formal
parameters were consumed when `param_2` is unused, and exceeded the fixture's
partial-decoder coverage in several exhaustive statements.

The next run pins the semantic gate in every evidence context, splits those
return facts by source, hard-codes the exact packet/slot tokens, bans the known
overclaims, and moves only E04's artifact checkpoint from result 10 to 14. The
incident also found a supervisor race: manually starting a second watchdog
could overwrite the registered watchdog heartbeat. A PID ownership preflight
now rejects foreign watchdogs before sidecar or state mutation; the harness
passes 42/42 reciprocal tests.

### Startup-ABI r7 semantic-admission result

Run `20260825-startup-abi-wave3-r7` demonstrated that successful transport and
schema validation are not the same as admissible decompilation evidence. All
four E workers completed and checkpointed within their frozen budgets, and the
then-current formal validator published an E manifest. A separate manual
semantic review rejected three artifacts, so no O-stage worker was launched.

| Worker | Result | Technical | Operational | Tokens | Calls |
|---|---|---:|---:|---:|---:|
| E01 caller packet | admitted | 96 | 94 | 57,234 | 6 |
| E02 stack reads | rejected | 84 | 60 | 62,014 | 7 |
| E03 frame/return | rejected | 88 | 96 | 93,254 | 7 |
| E04 leaf triage | rejected | 71 | 40 | 57,533 | 10 |

The run used 270,035 tokens and 30 completed tool results. Mean technical score
was 84.75 and mean operational score was 72.5, but only one of four artifacts
was admissible. E03 encountered one explicit HTTP 429 after its artifact was
already persisted, recovered, and completed; no quota or account failure was
observed.

The rejection reasons were substantive. E02 cited the wrong authority for its
entry layout and normalized post-push operands with a constant frame size. E03
omitted four authenticated local accesses, the transient stack effect at
`0x100ed434`, individual later caller rows, and misstated the number of
canonical returns. E04 appended prose to five frozen decision tokens, skipped
the admitted release callee, mislabeled allocation bookkeeping, and made
unsupported platform and pointer-semantic claims.

This run exposed an orchestration flaw rather than a rate-limit problem: the
manual semantic check happened after formal state publication. The supervisor
now supports a hash-pinned, stage-specific semantic gate that executes before
any manifest or validated-state write. Its reciprocal harness passes 44/44,
and the corrected E03 contract has dedicated regression tests. The operational
conclusion remains unchanged: ox-alpha is valuable for narrow evidence and
donor work, but artifact admission must be supervisor-owned and oracle-backed.

### Startup-ABI r8 pre-publication rejection

Run `20260825-startup-abi-wave3-r8` was the first live test of the integrated
pre-publication semantic gate. All four workers completed and checkpointed, but
`Validate -Stage E` rejected E03 because it renamed and bundled the mandatory
`E03.canonical-return-count=ONE_BARE_RETURN` fact. The E stage remained
`completed`, with no validated timestamp, no manifest path/hash, and no E
manifest on disk. No O worker launched. This is the intended failure mode.

| Worker | Result | Technical | Operational | Tokens | Calls | 429s |
|---|---|---:|---:|---:|---:|---:|
| E01 caller packet | admitted | 97 | 96 | 56,805 | 6 | 0 |
| E02 stack reads | rejected | 88 | 96 | 60,384 | 6 | 0 |
| E03 frame/return | rejected | 89 | 79 | 112,870 | 9 | 0 |
| E04 leaf triage | rejected | 86 | 58 | 106,306 | 13 | 1 |

The run used 336,365 tokens and 34 completed tool results. Mean technical score
was 90.0 and mean operational score was 82.25, but again only one of four
artifacts was independently admissible. E04's one explicit 429 named the shared
upstream Stealth pool, recovered automatically, and was not a quota, account, or
BYOK failure.

Independent grading found gaps beyond the first automated rejection. E02 called
the `0x100ed50b` store a read, overstated what the bounded direct-ESP scan proves,
and merged a canonical observation with a machine-level inference. E03 omitted
the `0x100ed4b0`/`0x100ed4ba` local writes and later called the authenticated
caller-position-3 operand at `0x100ed434` a local. E04 exceeded its role-specific
claim cap, misclassified several interpretive claims as direct, bundled
cross-source absence assertions, and did not reread or validate its entire
artifact. Across workers, many purported extractor commands were prose or
command-line pseudocode rather than reproducible Pi tool arguments.

The next configuration is versioned rather than mutating r8's frozen inputs. Its
v2 semantic gate adds source-pinned local/access rows, scan and classification
restraints, role-specific claim counts, required inference flags, atomic E04
boundary/header/platform facts, and parseable single-tool `read`/`grep` recipes.
The reciprocal v2 suite covers 36 cases, and the old r8 artifacts fail the new
checks for the defects above. The evidence-stage lesson is quantitative: high
technical donor scores do not predict autonomous admission, so independent
grading remains a required gate rather than a retrospective quality metric.

### Startup-ABI r9 closed-world result

Run `20260825-startup-abi-wave3-r9` exercised the fully hardened 38-fact
closed-world evidence contract. All four workers completed in one attempt and
checkpointed within budget. The supervisor then performed exactly one E-stage
validation. It failed before publication: the E stage has no validated
timestamp, manifest path/hash, or manifest file, and no O worker launched.

| Worker | Result | Technical | Operational | Tokens | Calls | 429s |
|---|---|---:|---:|---:|---:|---:|
| E01 caller packet | rejected | 97 | 84 | 60,379 | 6 | 0 |
| E02 stack reads | rejected | 98 | 88 | 45,958 | 5 | 0 |
| E03 frame/return | rejected | 99 | 86 | 75,593 | 8 | 0 |
| E04 leaf triage | admitted by the semantic gate | 100 | 96 | 94,834 | 13 | 0 |

The run used 276,764 tokens and 32 completed tool results. Mean technical score
was **98.5** and mean operational score was **88.5**, but autonomous admission
remained only **1/4**. No explicit HTTP 429, retry, throttle, quota, account, or
BYOK failure was recorded.

Unlike r7 and r8, independent grading found no substantive x86, ABI, source,
hash, inference, count, recipe, or conclusion error. The sole defect was
correlated exact-token noncompliance: every E01, E02, and E03 claim used
`locator="complete"` where the prompt and semantic gate required
`locator="complete source"`. The gate reported all 26 affected claims and no
other issue. Independent locator-only counterfactuals produced zero issues for
each rejected worker. E04 used the exact token on all twelve claims and passed.

This is strong donor quality but still a failed autonomous delivery result. The
generic evidence schema had accepted any nonempty locator, so three workers
mistook schema validity for semantic validity despite the exact prompt. The
versioned retry uses `pi_wave3_abi_evidence_v2.schema.json`, which makes
`kind="contract"`, `locator="complete source"`, and `blockers=[]` ordinary
schema constraints. Its regression accepts r9 E04 and rejects the exact r9 E01
locator mutation. The v3 configuration validates at the unchanged 3.48M-token
ceiling; the semantic gate passes 57/57 tests, the supervisor harness passes
46/46, and the native x64 build passes 31/31 tests without changing the
production DLL or host hashes. Frozen r8/r9 inputs remain byte-identical.

### Startup-ABI r10 evidence admission and oracle rejection

Run `20260825-startup-abi-wave3-r10` used the versioned evidence schema that
moved the exact locator/kind/blocker contract into ordinary JSON validation.
All four E workers completed in one attempt, passed the 38-fact semantic gate,
and were published in E manifest `f1890177...acedf`.

| Worker | Result | Technical | Operational | Tokens | Calls | 429s |
|---|---|---:|---:|---:|---:|---:|
| E01 caller packet | admitted | 99 | 96 | 65,817 | 6 | 0 |
| E02 stack reads | admitted | 100 | 94 | 47,870 | 5 | 1 |
| E03 frame/return | admitted | 100 | 98 | 74,386 | 7 | 0 |
| E04 leaf triage | admitted | 100 | 96 | 78,333 | 12 | 0 |

Evidence used 266,406 tokens and 30 completed tool results. Mean technical
score was **99.75**, mean operational score was **96.0**, and autonomous
admission was **4/4**. E02 encountered one shared-upstream-pool HTTP 429 and
recovered in the same attempt after about 40 seconds. It was not a quota,
account, or BYOK failure. The retry therefore validates the process change:
the correlated r9 transport defect disappeared without relaxing semantic
content.

The four O workers then completed in one attempt and passed the existing
structural validator, which published O manifest `197d12c4...c1be1d`.
Independent semantic grading rejected all four before I launch:

| Worker | Formal result | Semantic result | Technical | Operational | Tokens | Calls | 429s |
|---|---|---|---:|---:|---:|---:|---:|
| O01 raw packet | validated | rejected | 96 | 96 | 76,431 | 7 | 0 |
| O02 stack flow | validated | rejected | 61 | 97 | 60,555 | 7 | 0 |
| O03 empty slice | validated | rejected | 74 | 96 | 78,136 | 8 | 0 |
| O04 containment | validated | rejected | 66 | 78 | 47,536 | 6 | 0 |

Oracle use was 262,658 tokens and 28 completed tool results. Mean technical
score was **74.25** and mean operational score was **91.75**. Formal structural
admission was 4/4, but independent semantic admission was **0/4**. No O worker
recorded a 429 or retry.

The defects were actionable rather than cosmetic. O01 turned the bounded
direct-ESP scan into an unqualified absence claim. O02 used the wrong rel32
equation, propagated stack state across deliberately sparse rows, misstated the
loop graph, and did not require gap-free decoding of all 400 bytes. O03 had no
pinned PE for its proposed rehash, attributed raw offsets/hashes to an index
that lacks those columns, overbroadly scanned for allocator references, and
made all eight mutants families of alternatives rather than single executable
changes. O04 used the instruction rather than next-instruction VA for rel32,
overstated register instability, confused inert recovered identifiers with
linkage, required an impossible global absence of preexisting `0x100d6560`
legacy aliases, and could not observe its outside-workspace-write mutant.

This exposed the same publication-order class previously fixed for E: O's
schema/reciprocity/requirement checks prove transport structure, not that a
pristine baseline passes or that a paired mutant is executable and killed. I
remains locked. The next version adds an exact-eight transport schema, a
stage-specific semantic gate, pinned authorities for every proposed procedure,
single deterministic mutants, and regression cases for every r10 defect before
a fresh E/O run.

The r10 telemetry also resolved a configuration discrepancy. Pi 0.84.3's
current ox-alpha catalog supports `low`, `high`, and `max`, but not `medium`.
Although all eight frozen prompts requested `medium`, Pi's capability clamp
searches upward first and recorded/sent `high` to OpenRouter for every session.
This is real request behavior (`reasoning.effort=high`), not cosmetic metadata.
R10 provides no matched control with which to attribute token use, latency, or
its one recovered 429 to reasoning effort. The next configuration therefore
uses explicit `high` to preserve observed behavior while making the contract
truthful; any future cost trial must compare explicit `low` against `high`
rather than request unsupported `medium`.

### Startup-ABI r11 provider retirement

Run `20260826-startup-abi-wave3-r11` did not exercise worker quality. All four
E workers received the same immediate HTTP 404 announcing retirement of the
`ox-alpha` alias and pointing to `z-ai/glm-5.3-flash`. They produced zero
tokens, tool calls, artifacts, or source writes. This was not a 429, auth,
quota, account, or BYOK failure, and it is unrelated to cybersecurity or the
legitimacy of the decompilation work.

The supervisor contained the provider failure safely: E failed, every
downstream stage remained pending, and no manifest was published. Autonomous
delivery was **0/4**, but all four failures were one correlated provider event;
technical quality is therefore **N/A** and r11 is excluded from the model-quality
mean. Supervisor containment scores **94/100**, with minor deductions because
the remaining staggered workers launched after E01 had already returned the
definitive retirement response and because `process_exit_utc` remained null.

Preserve r11 as forensic evidence; do not validate, reuse, or delete it. The
measured operating recommendation remains **four live workers with a four-second
launch stagger**, with **six** as the maximum useful concurrency, not twenty.
The successor must be introduced through a new versioned configuration and a
fresh run rather than by modifying r11's frozen inputs.

### Startup-ABI r13 GLM evidence benchmark

Run `20260826-startup-abi-wave3-r13` is the frozen historical GLM evidence
benchmark. It used `openrouter/z-ai/glm-5.3-flash`; all four E workers were
admitted, and the published E manifest has SHA-256
`108260c51c04a2306f99aaa791a738399a7dfed1a810c75e4342b4453e06b8b5`.

| Worker | Result | Technical | Operational | Tokens | Calls | Cost | 429s |
|---|---|---:|---:|---:|---:|---:|---:|
| E01 entry/relocation | admitted | 100 | 92 | 52,548 | 6 | $0.002851525 | 0 |
| E02 stack layout | admitted | 100 | 96 | 45,425 | 5 | $0.001946450 | 0 |
| E03 frame/return | admitted | 100 | 96 | 71,720 | 7 | $0.003179415 | 0 |
| E04 leaf triage | admitted | 99 | 92 | 111,957 | 14 | $0.004500305 | 0 |

The stage used 281,650 tokens, 32 completed calls, and $0.012477695. Mean
technical and operational grades were **99.75** and **94.0**, respectively,
with autonomous admission **4/4**. There were no explicit 429s, retries,
provider errors, or tool errors. E04's artifact was independently correct, but
its answer-table-style reasoning consulted the semantic-gate material visible
in that historical worker context; that process defect accounts for part of
its operational deduction and limits later model comparisons.

### Startup-ABI r14 DeepSeek watchdog false positive

Run `20260826-startup-abi-wave3-r14` was the first frozen
`opencode-go/deepseek-v4-flash` attempt. It ended `watchdog_failed`, so no
manifest was published and there is no manifest hash.

| Worker | Frozen result | Grade | Tokens | Calls | Cost | 429s |
|---|---|---:|---:|---:|---:|---:|
| E01 | artifact completed, exit 0 | N/A | 58,634 | 6 | $0.006649024 | 0 |
| E02 | artifact completed, exit 0 | N/A | 48,369 | 6 | $0.004936372 | 0 |
| E03 | stopped before observable response | N/A | 0 | 0 | $0 | 0 |
| E04 | stopped before launch evidence | N/A | 0 | 0 | $0 | 0 |

Observable use was 107,003 tokens, 12 calls, and $0.011585396. The stop reason
was `Session JSONL was not created within 60 seconds`. Pi could defer creating
or flushing that file until the first assistant response, so a slow first
response was misclassified as a dead session; the supervisor then failed
closed and stopped the remaining workers. Subsequent simultaneous, staggered,
persistent, and tool-enabled four-way canaries passed, providing no evidence
of a hard concurrency-four limit. There was also no explicit 429, provider, or
API error. E01 and E02 remain donor/benchmark artifacts only; r14 was neither
resumed nor validated, and assigning model-quality grades to this harness
false positive would be misleading.

### Startup-ABI r15 DeepSeek exact-token rejection

Run `20260826-startup-abi-wave3-r15` completed all four E workers with the
exact `opencode-go/deepseek-v4-flash` binding, but semantic admission rejected
the stage. No E manifest was published, so there is no manifest hash.

| Worker | Frozen result | Grade | Tokens | Calls | Cost | 429s |
|---|---|---:|---:|---:|---:|---:|
| E01 | completed; stage not admitted | N/A | 61,735 | 6 | $0.007296740 | 0 |
| E02 | exact-token rejection | N/A | 51,902 | 5 | $0.005541472 | 0 |
| E03 | completed; stage not admitted | N/A | 76,144 | 8 | $0.010127400 | 0 |
| E04 | completed; stage not admitted | N/A | 84,796 | 12 | $0.009972728 | 0 |

The stage used 274,577 tokens, 31 calls, and $0.032938340. All workers exited
0 and checkpointed, with no structured provider, tool, or assistant errors and
no explicit 429/rate-limit events. Incidental `429` character sequences in a
SHA fragment are not rate-limit evidence.

The rejection was narrow and deterministic: E02 added a trailing semicolon to
each of `E02.entry-layout`, `E02.consumed-positions`, and
`E02.local-access-rows`. Semicolons in the prompt separated claim
specifications, making the delimiter look like part of the required exact
value. This was a prompt-punctuation/root-contract defect rather than a
reported ABI fact error. The frozen dependency and manifest design required
all E01--E04 artifacts from one admitted run, so an E02-only donor graft was
not admissible; a fresh full-E run was required. No independent per-worker
technical or operational grades were frozen for r15.

### Startup-ABI r16 DeepSeek E admission and O rejection

Run `20260826-startup-abi-wave3-r16` corrected the E02 exact-value wording and
admitted all four E workers under `opencode-go/deepseek-v4-flash`. The
published E manifest has SHA-256
`12a980aff53559e1b8079676538036067fedbe55943237166a6339be6adec8b2`.

| Worker | E result | Technical | Operational | Tokens | Calls | Cost | 429s |
|---|---|---:|---:|---:|---:|---:|---:|
| E01 | admitted, exit 0 | 100 | 96 | 63,240 | 6 | $0.007480000 | 0 |
| E02 | admitted, exit 0 | 100 | 96 | 58,743 | 6 | $0.007314084 | 0 |
| E03 | admitted, exit 0 | 100 | 96 | 71,226 | 8 | $0.009107472 | 0 |
| E04 | admitted, exit 0 | 100 | 96 | 107,287 | 13 | $0.011621916 | 0 |

E used 300,496 tokens, 33 calls, and $0.035523472. Every checkpoint was
present, and there were no explicit 429s or provider, tool, assistant, or
structured errors. Independent fact-by-fact grading admitted 4/4 at mean
technical **100** and operational **96**. E02 and E03 matched the admitted r13
facts field-for-field; E04 differed only in claim ordering; E01 used the
explicitly permitted hash-identical absolute read paths. Each worker lost four
operational points only for a verbose final response instead of the requested
readiness-only sentence.

The same run's O stage was rejected as `budget_exceeded`; no O manifest was
published and there is no O manifest hash.

| Worker | O terminal result | Technical | Operational | Checkpoint | Tokens | Calls | Cost | 429s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| O01 | exit 0; over budget | 87 | 68 | yes | 194,833 | 7 | $0.044321588 | 0 |
| O02 | exit 0; over budget | 64 | 54 | yes | 165,306 | 6 | $0.030767168 | 0 |
| O03 | stopped; no checkpoint receipt | 63 | 28 | no | 153,548 | 11 | $0.028934576 | 0 |
| O04 | stopped before final turn | 47 | 25 | yes | 259,013 | 9 | $0.033358012 | 0 |

O used 772,700 tokens, 33 calls, and $0.137381344. Every worker exceeded the
frozen 150,000-token ceiling. O01 and O02 finished naturally but were correctly
rejected; O03 and O04 were stopped before complete final delivery. There were
no explicit 429s, retries, or provider/tool/API errors. Independent donor
grading was 0/4 admission, mean technical **65.25**, and mean operational
**43.75**. The drafts exposed wrong mutation loci and stand-in mutations that
could fail for unrelated reasons, plus an O gate still hard-bound to the old
v5 config hash. Thus the rejection was not merely an undersized budget: r16 O
requires a fresh run with a versioned active-config gate, structured mutation
contract, exact semantic kill checks, and calibrated per-role budgets.

### Current provider policy and comparison limits

The current operator policy retires ox-alpha, whose alias ended with the r11
404, and uses `opencode-go/deepseek-v4-flash`; no GLM workers will be launched
going forward. This is a prospective operating decision only. It does not
rewrite or invalidate the frozen historical ox-alpha or GLM evidence above.

R13 GLM E and r16 DeepSeek E are useful descriptive benchmarks, not a
controlled head-to-head. R13 used an older prompt/harness with answer-bearing
semantic-gate material visible to workers, while r16 used revised exact-value,
session-isolation, and startup controls. They also used different provider
routes and pricing. GLM r13 admitted 4/4 with 281,650 tokens, 32 calls, and
$0.012477695; DeepSeek r16 admitted 4/4 with 300,496 tokens, 33 calls, and
$0.035523472. The latter is 18,846 tokens (about 6.7%) and one call higher, but
neither the route cost nor quality grades are apples-to-apples. R14's harness
false positive and r15's punctuation-driven exact-token rejection likewise
must not be counted as clean model-quality losses.

### Local Qwen r1 evidence calibration

Run `20260826-local-qwen-abi-benchmark-r1` is a donor-only calibration of
`llamacpp-local/qwen3.8-27b-q4-dflash2`. The local llama.cpp server was bound
to `127.0.0.1`, advertised one parallel slot, and Pi ran every worker
sequentially with hosted-provider credential variables removed from the child
environment. Every session `model_change` and all twenty assistant messages
recorded exactly `provider=llamacpp-local` and
`model=qwen3.8-27b-q4-dflash2`.

The calibration reused the r16 E01--E04 prompts and frozen contexts, changing
only the route, isolated workspace paths, and immaterial trailing blank lines.
It is therefore comparable to r16 for bounded instruction following, but it
has no supervisor state, stage manifest, or publication authority. Its output
must not be grafted into an admitted run.

| Worker | Donor result | Technical | Operational | Tokens | Calls | Elapsed | Reported API cost |
|---|---|---:|---:|---:|---:|---:|---:|
| E01 | admissible, exit 0 | 100 | 96 | 65,549 | 6 | 45 s | $0.00 |
| E02 | admissible, exit 0 | 100 | 96 | 56,671 | 5 | 34 s | $0.00 |
| E03 | admissible, exit 0 | 100 | 96 | 76,798 | 7 | 79 s | $0.00 |
| E04 | admissible, exit 0 | 100 | 96 | 88,250 | 12 | 88 s | $0.00 |

All four documents pass `pi_wave3_abi_evidence_v2.schema.json`, and their
complete evidence root passes `pi_startup_abi_evidence_gate_v2.py`. Independent
grading found all 38 claims, sources, hashes, inference flags, counts, and
frozen conclusions correct. The only model writes were the four isolated
`evidence.json` files; each checkpoint was timely and each artifact was
re-read exactly once. There were no tool errors, retries, 429s, provider
errors, or nonzero exits. As in r16, each worker lost four operational points
for adding validation detail after the requested readiness-only final sentence.

The run totals were 287,268 accounting tokens, 30 calls, 246 cumulative
worker-seconds, and $0.00 reported API cost. Local electricity, hardware,
quantization effects, and backend token accounting are not included in that
cost. Compared descriptively with r13 GLM, local Qwen used 5,618 more tokens
(2.0%), two fewer calls, and scored 100/96 rather than 99.75/94. Compared with
r16 DeepSeek, it used 13,228 fewer tokens (4.4%), three fewer calls, tied the
100/96 grade, and took 246 rather than 179 cumulative worker-seconds. Qwen's
four workers were necessarily sequential; the hosted runs were concurrent,
so end-to-end stage throughput is not directly comparable.

These prompts contain the frozen answer contract. The result is strong evidence
that this local Qwen is useful for exact, bounded artifact work; it is not yet
evidence that Qwen matches DeepSeek on independent decompilation discovery,
architecture, mutation-oracle design, or implementation repair.

### Startup-ABI r17: admitted evidence/oracles, failed implementation stage

Run `20260826-startup-abi-wave3-r17` used the exact
`opencode-go/deepseek-v4-flash` route. E admitted 4/4 with manifest SHA-256
`324c5e25c6cca48a980ed4ff2aa38a400e5e0458bc0207fe6c34790d239ef50a`;
O admitted 4/4 under the hardened 32-mutant gate with manifest SHA-256
`8089fd9bfcad71cd041f0d79c8df69bf4b0fe049b8412fecb69493ac82f69d85`.
E used 279,937 tokens and 33 calls; O used 674,122 tokens and 33 calls. There
were no explicit 429s, retries, or provider errors at four-way concurrency.

The six-worker I stage is a sharp negative result. All six exceeded the
220,000-token worker cap, no submission manifest was published, and R/G were
correctly left pending. I used 1,641,464 observed tokens and 104 declared tool
calls. Six partial Python implementations survived in isolated workspaces, but
none passed pristine acceptance as delivered:

| Worker | Direct rerun result | Salvage code grade | Principal defect |
|---|---|---:|---|
| I01 | auditor rejects pristine; test does not parse | 41 | four fixture/schema failures plus a literal prose line causing `SyntaxError` |
| I02 | crashes on invocation | 28 | fixture key `caller_packet_handler_registered` does not exist; no tests |
| I03 | negative suite 14/15; pristine rejected | 60 | rejects the valid split `body_ranges` row for `0x100edd70` |
| I04 | 16/17 checks pass | 66 | pop-ESI opcode indexed from `0x50` instead of the `0x58` pop base; no candidate tests |
| I05 | zero tests run | 33 | PE parser fails to locate the real `.text` section |
| I06 | 7 tests pass, 4 fail, 5 error | 43 | pristine auditor raises `TypeError` and omits the expected report sections |

The failure-inclusive mean code grade is **45.2/100**; zero of six reached 70,
and verbatim admission is 0/6. The grades credit safe read-only intent and
substantial provenance work, but autonomy is zero because every worker missed
its budget and terminal artifact contract. I04 is the best donor and appears
one small defect from a clean real-corpus report, but without reciprocal tests
it is still not an admitted tool.

This changes the process decision. DeepSeek remains worthwhile for exact,
bounded E/O artifacts with an external gate. Six-way hosted concurrency showed
no rate-limit problem. Broad "build the complete auditor" packets are not
worth running as a swarm: they consumed 1.64M tokens, converged on incomplete
deliverables, and delayed executable work. Implementation packets should fit
one source/test seam, require a runnable artifact by an early call, and be
terminated on a failed pristine smoke before more analysis.

### Local Qwen bounded independent audit

After the exact-answer calibration, local
`llamacpp-local/qwen3.8-27b-q4-dflash2` received a ten-call, read-only audit of
`0x100ec5c0`. It efficiently found all decompiler return statements and the
parent's 0/1/2 comparisons, so it was useful as source navigation. Independent
raw disassembly invalidated the central conclusion and several proposed pins:

- Ghidra's synthetic `swi(3)` is raw opcode `CC` (`INT3`), not an indirect
  call returning an arbitrary value;
- the full-body raw offset is `0x000eb9c0`, not `0x000ec5c0`;
- the parent call is at `0x100ed4c5` and comparisons begin at `0x100ed4ca`,
  four bytes earlier than reported;
- the proposed full side-effecting native seam was far broader than the safe
  evidence-only boundary.

The independent-audit report scores **51/100** under the report rubric: useful
and efficient navigation, but not reliable enough to authorize raw control-flow
or native API decisions. This reconciles the apparently exceptional 100/96
calibration: local Qwen is strong when reproducing a frozen answer contract,
but materially weaker on independent binary adjudication. Keep it serial and
bounded; require supervisor raw-byte verification before implementation.

### Local Qwen ad hoc boundary audit reliability check

A second bounded task asked the same local model to audit `0x100df270` as an
independent reviewer. Three serial Pi attempts were unusable: the normal
read-only invocation exited after printing unevaluated tool-call markup; the
attachment-only/no-tools retry still requested tools; and a strict no-tools
system prompt produced only 562 tokens before terminating halfway through its
effect table. No final recommendation or complete artifact was delivered.

This attempt receives **0/100 delivery credit** and is excluded from technical
accuracy averages because there is no complete answer to grade. The partial
table did navigate the canonical source in roughly the right order, but it did
not reach the raw-byte boundary question. There was no rate limit or hosted
provider error: this was a local Pi/model tool-protocol and completion
reliability failure. The process rule is now narrower: use local Qwen through
the already-proven structured harness for serial exact-answer work; do not rely
on ad hoc local Qwen tool use for an implementation gate. Raw PE provenance,
native tests, and supervisor review remain authoritative.

### DeepSeek bounded review of the `0x100df270` projection

One post-implementation review used exactly
`opencode-go/deepseek-v4-flash`, attachment-only and read-only. It eventually
delivered a correctly formatted review after several minutes with no 429,
retry, provider error, or tool call. It accurately checked every implemented
offset and width, the span/alias arithmetic, adjacency behavior, and the fact
that all rejection paths precede the first write.

Its main rejection was wrong. It decoded the call at `0x100f1ab4` as targeting
`0x100ee330`; the signed rel32 actually resolves to `0x100ef330`. The already
admitted `0x100f1aa0` fixture pins that target and its exact 23-byte zero branch,
including the `0x11af4090` store without reading the collapsed source
arguments. Consequently three claimed high-severity oracle defects and the
final `REVIEW: REJECT` verdict do not survive raw adjudication.

The review did find one concrete minor gap: the final 15-byte x86 epilogue was
covered by the full 640-byte body hash but not separately characterized in the
new document/window list. That window is now pinned explicitly. The new seam
verifier also duplicates the previously admitted `0x100ef330` zero-branch proof
so an attachment-only reviewer can verify the transitive output locally.

Grade: **62/100 technical, 88/100 operational**. This is useful reviewer
behavior under tight scope, but the incorrect rel32 arithmetic shows why
DeepSeek suggestions must still be resolved mechanically. The run shows slow
latency, not rate limiting.

### Supervisor self-grade: direct `0x100f2750` implementation slice

This slice was completed directly by Codex without Pi, hosted models, local
Qwen, or Codex subagents. It therefore measures end-to-end supervisor work,
not swarm throughput, and benefits from unrestricted access to the accumulated
repository context.

Technical grade: **95/100**.

| Category | Score | Basis |
|---|---:|---|
| Raw evidence and provenance | 25/25 | Pins the full body, accepted and excluded routes, rel32 targets, helper entry/tail, threshold proof, parent call site, canonical sources, and index rows. |
| Fixed-width API safety and atomicity | 24/25 | Guest32-only public shape, complete host/guest range and alias checks, validation before writes, and unchanged failure outputs; one point withheld because the defensive view-validation logic remains locally duplicated rather than shared through one admitted writer primitive. |
| Semantic fidelity of the admitted subset | 18/20 | Exact unsigned capacity decision, equal-descriptor no-op, `2 * (count + 1)` width, scalar forward copy, and final count commit; two points withheld because there is no differential execution against the original x86 body and overlap/large-copy behavior is intentionally outside the subset. |
| Tests, mutants, and containment | 18/20 | Boundary, adjacency, cross-alias, overflow, failure-atomicity, CMake/export, and reciprocal mutation coverage all pass; two points withheld for the absence of randomized/property testing and a guarded-page native fault harness. |
| Integration, documentation, reproducibility | 10/10 | Headless execution, 56-route CTest chain, clean testing-on/off builds, unchanged shipped hashes, updated manifest, and a bounded design record. |

Operational grade: **94/100**. The work reached a complete runnable artifact
and clean verification without delegation. Deductions cover one initial MSVC
build attempted without the developer environment, an early static-gate
ordering/parser false positive, and several adjacency/cross-alias cases added
only during the final self-review. All were corrected before admission; none
is a residual product failure.

The combined **94.5/100** is materially above the recorded agent submissions,
but it is not a fair cost comparison: the supervisor had the full historical
context, could iterate without a worker token cap, and owned integration and
adjudication. The useful process conclusion is that direct supervisor work is
currently the better route for semantics-bearing implementation slices, while
DeepSeek remains most cost-effective for narrow evidence/oracle artifacts that
are mechanically gated.

### DeepSeek review of the complete `0x100e2460` preallocated branch

A fresh read-only Pi review used exactly
`opencode-go/deepseek-v4-flash` after the branch implementation and expanded
runtime oracle were present. The first session inherited across the workstation
restart stalled without output and was replaced; the fresh session completed in
about three and a half minutes. Neither session emitted a 429, retry notice, or
provider error, so this is latency/session-recovery evidence rather than a rate
limit.

The completed review correctly decoded the append/count order, thiscall
receiver and vtable `+4` method selection, saved-`AL` lifetime, five-argument
Peek shape, loop polarity, checked arithmetic, and CMake fixture graph. It found
no blocker and scored core, tests, and integration **9/10** each. Its most useful
finding was the missing `max_peek_calls == 1` drain-limit case; that boundary is
now tested. Its other low finding treated permitted read-only state/vtable host
overlap as an incomplete alias matrix. No unsafe access followed from that
policy, but the public contract now says explicitly that the overlap is allowed
and that the resolved method cell remains disjoint from both pending writes.
The review's opening summary also misstated the authenticated partition as
30/175/47 bytes; the pinned and independently rechecked split is 29/176/47.
That reporting error did not affect its instruction-level findings, but it is
another reason the model's narrative is not accepted as provenance authority.

Adjudicated grade: **87/100 technical, 84/100 operational**. The technical
review was accurate and actionable. Operational deductions cover the silently
stalled inherited session and multi-minute latency, not rate limiting. Across
the recent mixed generation and review packets, DeepSeek remains roughly a
**7.8/10** workhorse on average: worthwhile by default for bounded parallel
work, but generated semantics still require mechanical gates and supervisor
adjudication.

### Supervisor self-grade: complete `0x100e2460` preallocated branch

This milestone receives **94/100 technical** and **92/100 operational**, or
**93/100 combined**. The admitted branch is runnable, authenticated to exact
machine windows, fail-closed at the guest32 boundary, mutation-tested, and
verified 75/75 in two independent testing-enabled builds. Both fresh build
matrices reproduce the unchanged production DLL and host hashes, and all three
Ninja graphs are clean.

Deductions cover validation cases that were added only after independent audit,
one initially missing one-call drain boundary found by DeepSeek, and the absence
of differential execution against the original x86 routine. There is no known
residual product failure in the admitted branch. This remains a branch-scoped
achievement: allocator/growth routes, native USER32 behavior, the six real
handler methods, and complete game startup are still outside the port.

### DeepSeek admission review: `0x100f2750` sentinel-owned lifecycle

Three isolated read-only Pi sessions used exactly
`opencode-go/deepseek-v4-flash` for independent semantics, runtime-oracle, and
integration reviews. All three exited zero without a provider or retry error;
their prompts, reports, receipts, and sessions are retained under
`out/pi-swarm/20260831-sentinel-admission/`.

The reviews agreed that the implementation had no proved blocker and that the
smallest next seam is a bounded nonempty `[0x100ed3c0,0x100ed471)` composition.
The oracle review usefully found missing alignment cross-products, view-overflow
variants, build-path backing/control overlap, denial-token collision, and
teardown validation cases. Those cases are now in the 107-case runtime oracle.
The semantics review also caught stale integration prose and the distinction
between the compare at `0x100f275d` and the `JA` opcode at `0x100f2760`; both are
corrected. Its token-authority concern led to an explicit contract: denial must
leave a zero grant, while any nonzero callback-written token is fresh one-shot
release authority even when the result code is inconsistent.

One oracle claim was rejected during adjudication: it said the maximum
`N=32767` runtime boundary was absent, but that case was already present. The
other actionable findings were reproduced before being accepted. The admitted
result passes the hardened MSVC and AddressSanitizer oracle, the reciprocal
provenance/static gates, both 168/168 testing-enabled matrices, and the
testing-disabled containment/hash control. This run reinforces the established
pattern: DeepSeek is effective as a parallel adversarial reviewer, while exact
repository evidence and mechanical gates remain the admission authority.

### DeepSeek design and admission review: nonempty-parent prerequisite

Three isolated design reviewers using exactly
`opencode-go/deepseek-v4-flash` unanimously rejected direct composition of the
nonempty `0x100ed3c0` parent as too broad. They correctly identified the
blocking contract mismatch: the admitted `0x100df270` suffix exposed the
observed `CALL_100F2750` only through a non-executing observer, so running the
persistent write before or after the suffix would reorder it and running it
inside the observer would violate that callback contract. Their retained
reports under `out/pi-swarm/20260831-nonempty-preloop-design/` selected the
narrower typed, status-returning mid-suffix delegate now implemented here.

The first post-implementation admission wave is retained under
`out/pi-swarm/20260831-suffix-delegate-admission/`. Its semantics reviewer
returned `ADMIT`; its oracle and gate reviewers returned `FIX` for real
coverage gaps rather than behavioral defects. Those reviews added delegated
replays of all 25 baseline precommit failures, descriptor/output and same-cell
aliases, named delegated step/helper checks, and body-scoped reciprocal
mutants, growing the runtime from 48 to 75 cases. A corrective rereview under
`out/pi-swarm/20260831-suffix-delegate-rereview/` then found the last copied-code
blind spot: delegated effects snapshotting had no mutation adversary, and three
preflight lines plus the delegated conditional route lacked dedicated named
mutants. The resulting 76th case and gate changes close those gaps.

The final oracle under
`out/pi-swarm/20260831-suffix-delegate-final-review/` returned `ADMIT` and
confirmed that the new effects mutation is discriminating: caller mutation
persists while every later observation uses the snapshot. The paired final
gate worker became trapped in repetitive read-only tool calls and was
terminated without a report; this is an operational failure, not an admission
authority. Its preceding complete gate rereview specified the corrections now
present, while the live 12/12 reciprocal suite, zero-finding gate, all 367
startup static-gate tests, hardened analysis/AddressSanitizer run, and three
independent 168/168 CTest graphs supply the mechanical verdict. This sequence
is a particularly good example of the intended division of labor: DeepSeek
found high-value omissions, and deterministic repository checks adjudicated
and froze each accepted finding.

### DeepSeek admission review: nonempty `0x100ed3c0` parent

The implementation-design wave retained under
`out/pi-swarm/20260831-nonempty-preloop-implementation-design/` used exactly
`opencode-go/deepseek-v4-flash`; its contract, oracle, and gate reviewers all
returned `READY`. A subsequent read-only code audit under
`out/pi-swarm/20260831-nonempty-preloop-code-audit/` found one real defensive
owner-leak branch. The branch was repaired before admission, and the oracle
review returned `READY`.

The fresh admission wave under
`out/pi-swarm/20260831-nonempty-preloop-admission-audit/` returned `READY` from
both gate and source reviewers. The source worker was operationally slow and
was interrupted after roughly 20 minutes just as it completed; its report and
zero exit receipt were retained, with no provider or rate-limit error. The
mechanical authority is the 48-case total-order runtime oracle, 19/19 reciprocal
gate tests, zero-finding live gate, strict MSVC analysis, AddressSanitizer run,
three independent 180/180 testing-enabled CTest graphs, and the testing-disabled
containment/hash control. Production DLL and host hashes remain unchanged.

### DeepSeek admission review: whole nonempty ordinary lifecycle

The whole-parent code audit retained under
`out/pi-swarm/20260831-nonempty-lifecycle-code-audit/` used exactly
`opencode-go/deepseek-v4-flash`. Its oracle reviewer returned `READY`; its
source reviewer returned `REVISE` while the child gates still carried the
174-test checkpoint and before the complete current matrix had run. The
accepted low-severity oracle findings also added full combined-result and
persistent-descriptor assertions, direct context-to-control and
control-to-backing alias cases, and mismatch-route qualification for the
31-event preloop constant.

After those corrections, the final code/contract and evidence/containment
reviewers under
`out/pi-swarm/20260831-nonempty-lifecycle-admission-audit/` both returned
`READY`, with exact-model launch receipts and zero exit receipts. The
mechanical authority is the 36-case total-order runtime oracle, 6/6 provenance
suite, 22/22 reciprocal mutation suite, zero-finding live gate, post-PE and
bootstrap-reload gates, and three independently executed 180/180
testing-enabled graphs. The testing-disabled control exposes zero tests and no
whole-composition target/source token. Focused CTest logs in
`out/analyze-100ed3c0-nonempty-lifecycle/Testing/Temporary/LastTest.log` and
`out/asan-100ed3c0-nonempty-lifecycle/Testing/Temporary/LastTest.log` each
retain `PASS (36 cases)` under their respective `/analyze /WX` and
AddressSanitizer builds.

Across the primary, both retained testing-enabled trees, and the
testing-disabled tree, the production DLL remains 107,520 bytes with SHA-256
`d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`
and the host remains 144,384 bytes with SHA-256
`be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.
The separately retained planning review under
`out/pi-swarm/20260831-nonempty-lifecycle-closeout/next-milestone/`
recommends the exact two-window `entry_point` caller-closure binder as the next
bounded slice and rejects synthesizing the ordinary-unreachable result-one
route.

### DeepSeek design and admission review: `0x100edd70` entry decision

The contract/oracle wave retained under
`out/pi-swarm/20260901-entry-decision-design/` and the mechanical pin audit
under `out/pi-swarm/20260901-entry-decision-implementation/` used exactly
`opencode-go/deepseek-v4-flash`. The design reports initially disagreed over a
three- versus four-record registration transcript. The exact-model tiebreak
resolved that ambiguity in favor of four structural records: the pushed handler
identity folds into its consuming call shape, while the physically separate
`add esp,4` remains its own record before the two frame stores.

The resulting test-only route composes the selector, conditional registration
data, and admitted caller closure. Its executable reruns the unchanged 54-case
child oracle before an exact 44-case outer registry. Primary and fresh
testing-enabled graphs both pass 192/192; the testing-disabled graph exposes
zero tests and no entry-decision token. Strict analyzer outputs for both new C
files contain empty `DEFECTS` sets, and the retained AddressSanitizer graph and
focused LastTest log record all 54 child and 44 outer cases passing. The three
production trees reproduce the unchanged DLL and host hashes.

The first source audit under
`out/pi-swarm/20260901-entry-decision-admission-audit/code-contract/` returned
`REPAIR` because it did not locate the separately retained analyzer and
sanitizer evidence; it found no composition defect and independently confirmed
the 44-case partition. The admission record now names the exact retained paths
and distinguishes those separate hardened runs from ordinary CMake flags. A
narrow rereview under `code-contract-rereview/` verified the artifacts and
returned `ADMIT` with no remaining blocker.

The paired successor audit under `next-seam/` returned
`EVIDENCE FREEZE FIRST`. It recommends treating the install-only nine-byte tail
`[0x100edf41,0x100edf4a)` and the shared 28-byte epilogue
`[0x100edf94,0x100edfb0)` as one convergence unit, while permanently keeping
the exception-dispatch gap `[0x100edf4a,0x100edf73)` pinned but non-executable.
The evidence and transcript/oracle design freeze for that unit is the next
active milestone; the pre-selector COM/IGameExplorer prefix remains the larger
successor after it.
