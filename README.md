# Cross-Site Placement

Cross-Site Placement is the deterministic cross-site placement planning and explanation
authority of the Data Center Control Plane. It answers one question: **given candidate
sites and explicit authoritative evidence, where should an obligation be placed so that
physical, policy, latency and dependency, failure-independence, and recoverability
constraints are satisfied?**

The answer is a deterministic, ordered plan or an explicit refusal. A plan names the sites,
the exact evidence records it relied on, the constraints it evaluated, what it could not
satisfy, and why it chose one arrangement over another. A plan is a proposal and an
explanation. It is not a reservation and not an effect: planning consumes no capacity, and
nothing in this library can apply a plan.

## What this boundary owns

* Placement planning: deciding which sites satisfy a stated set of obligations.
* Explanation: naming the rule that decided, the evidence behind it, and the residual
  requirements that remain unmet.
* Plan identity: a canonical encoding, a digest, and a derived identity for every plan.
* A durable journal of the plans this boundary has published, with a checked commit
  protocol and an explicit recovery story.

## What this boundary does not own

* Capacity brokerage and reservation commitment. Capacity offers and commitments arrive as
  references to somebody else's ledger, are read, and are recorded; they are never
  decremented, held, or created here.
* Site-capacity truth. A capacity reading is evidence, not a fact this boundary maintains.
* Failure-domain truth. The containment and alias structure is consumed, never authored.
* DFI route planning and network measurement. A path measurement is consumed with its
  provenance; this boundary never measures anything and never invents a number.
* ASI scheduling, disaster-recovery execution, and global policy authoring. A plan may
  require that a recovery alternative exists and that it can meet an objective; bringing it
  up is not this boundary's decision.

The architectural invariant is that this boundary owns one thing exactly, consumes
neighbouring truth explicitly, and never infers another runtime's authority. Every fact
about the world arrives through an evidence snapshot that names its own authority and
generation.

## The question it answers

A request states the obligations to place and what must be true about where they go:
service class, capacity per placement, how many primary and recovery placements are needed,
recovery objectives, allowed and forbidden sites, jurisdictions, failure-domain separation,
and latency bounds against other obligations or against services that already run somewhere.

An evidence snapshot states everything about the world: site identity, jurisdiction,
maintenance state, failure-domain containment and aliases, capacity references, directed
path measurements, recovery capability, service compatibility, and cost and risk.

A policy states which of the decisions this boundary cannot make from evidence are resolved
how: whether degraded sites are usable, whether an unreported maintenance state is usable,
whether an unrecorded jurisdiction satisfies a jurisdictional constraint, whether capacity
offers count as well as commitments, and whether a latency bound may be derived from a chain
of measurements.

## Building

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Debug, sanitizers, and the library-only build:

```
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug && ctest --test-dir build-debug --output-on-failure

cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCSP_SANITIZE=address+undefined
cmake --build build-asan && ctest --test-dir build-asan --output-on-failure

cmake -S . -B build-lib -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCSP_BUILD_TESTS=OFF -DCSP_BUILD_CLI=OFF -DCSP_BUILD_EXAMPLES=OFF -DCSP_BUILD_BENCHMARKS=OFF
cmake --build build-lib
```

The options are @CSP_BUILD_SHARED@ (off), @CSP_BUILD_TESTS@, @CSP_BUILD_CLI@,
@CSP_BUILD_EXAMPLES@, @CSP_BUILD_BENCHMARKS@, @CSP_INSTALL@, @CSP_WARNINGS_AS_ERRORS@ (on),
and @CSP_SANITIZE@ (empty, @address@, @undefined@, @address+undefined@, or @thread@ where the
toolchain supports it).

Nothing in this project has a timeout. The test harness has no watchdog, CTest targets carry
no @TIMEOUT@ property, and the CI workflow sets no @timeout-minutes@. A hanging test is a
defect to diagnose.

## Installing and consuming

```
cmake --install build --prefix /some/prefix
```

The install exports one namespaced target, @CrossSitePlacement::CrossSitePlacement@, a
package configuration usable through @find_package(CrossSitePlacement REQUIRED)@, and the
public headers. A consumer needs nothing else; the library uses only the C++20 standard
library and the platform's threading support, and the package configuration propagates the
thread dependency itself.

@examples/consumer@ is an independent project that is not part of the top-level build. It is
built only against an installed package:

```
cmake -S examples/consumer -B consumer-build -G Ninja -DCMAKE_PREFIX_PATH=/some/prefix
cmake --build consumer-build
./consumer-build/csp-consumer
```

## The command-line tool

@csp-cli@ is a real tool that exercises the boundary rather than a wrapper around one
function.

```
csp-cli version
csp-cli rules
csp-cli plan       --request R.json --evidence E.json --policy P.json [--now NANOS] [--pretty] [--out F]
csp-cli explain    --request R.json --evidence E.json --policy P.json [--now NANOS]
csp-cli verify     --plan F
csp-cli revalidate --plan F --request R.json --evidence E.json --policy P.json [--now NANOS]
csp-cli store      --dir D list
csp-cli store      --dir D load --plan PLANID
csp-cli store      --dir D audit
csp-cli store      --dir D commit --plan F
csp-cli store      --dir D compact
csp-cli gen        --sites N --seed S --classes N --out DIR [--now NANOS]
```

@csp-cli gen@ writes a self-consistent request, evidence snapshot, and policy drawn from a
seeded generator, which is the shortest way to get a realistic input to run the other
commands against. Every identifier it produces comes from the seed, never from a clock or an
address, so two runs with one seed produce identical documents.

The exit codes are part of the interface:

| Code | Meaning |
| ---- | ------- |
| 0 | the command succeeded, and for @plan@ and @explain@ the outcome is @planned@ |
| 1 | the planner refused: a proof that no arrangement satisfies the request |
| 2 | the planner could not decide, or a revalidation verdict was undecidable |
| 3 | an error: malformed input, contradictory evidence, a bound, an I/O failure, or cancellation |

Every failure prints @csp-cli: <category>: <code>: <message>@ to standard error and never a
partial plan. The tool reads the system clock for one purpose only: to supply the evaluation
instant when @--now@ is absent. The library itself never reads a clock, because two runs of
one logical request have to agree byte for byte.

## The library API

```c++
#include <cross_site_placement/cross_site_placement.hpp>

csp::PlacementPolicy policy = csp::policy_from_document(policy_text, limits).value();
csp::SiteEvidenceSnapshot evidence = csp::snapshot_from_document(evidence_text, limits).value();
csp::PlacementRequest request = csp::request_from_document(request_text, limits).value();

csp::PlanningContext context;
context.evaluation_instant = csp::Instant::from_nanos(now_nanos);
context.cancellation = source.token();          // optional

csp::Planner planner;                            // stateless; safe to share
csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
if (!planned) {
  // The question could not be evaluated: malformed input, contradictory evidence, a bound,
  // or cancellation. No plan exists.
  return planned.error();
}
const csp::PlacementPlan& plan = planned.value();
if (csp::plan_is_applicable(plan)) {             // outcome == planned
  for (const auto& obligation : plan.obligations) {
    for (const auto& placement : obligation.placements) {
      use(placement.site, placement.capacity.references);
    }
  }
}
```

Two failure kinds are kept apart deliberately. A @csp::Result@ carrying an error means the
question could not be evaluated. A @csp::Result@ carrying a plan means it was evaluated, and
the plan says whether an arrangement exists. Refusing to place something is an answer.

## Architecture

| Layer | Files | Responsibility |
| ----- | ----- | -------------- |
| Values | @strong_types.hpp@, @measurement.hpp@, @core.hpp@, @error.hpp@ | identities, exact integers, three-valued truth, the error model |
| Evidence | @evidence.hpp@, @limits.hpp@ | the consumed world and every bound |
| Question | @request.hpp@, @policy.hpp@ | what to place, and how the undecidable is resolved |
| Resolution | @domain_graph.cpp@ | transitive containment and alias-merged failure domains |
| Engine | @engine.cpp@, @engine_candidates.cpp@, @engine_latency.cpp@, @engine_search.cpp@ | the rule order, the search, the ordering |
| Answer | @plan.hpp@, @plan.cpp@ | the plan, its identity, and its digest |
| Text | @text.hpp@, @text_render.cpp@, @text_parse.cpp@ | the canonical encoding and the trust boundary |
| Durable | @persistence.hpp@, @store_format.cpp@, @persistence.cpp@ | the checked commit protocol and recovery |
| Platform | @fs_atomic.cpp@ | the only translation unit that includes a platform header |

The deterministic core is separated from I/O and from the platform. The planner is a pure
function of its arguments: it holds limits and nothing else, with no cache, no clock, no
mutable state, and no I/O. The only concurrency in the engine is bounded parallel evaluation
of a per-candidate predicate whose result is assembled in index order, so the answer does not
depend on how many workers ran.

## Data model and invariants

### Identities

Every identity is an opaque string from a documented alphabet: ASCII letters and digits plus
@-@, @_@, @.@, @:@, `, @+@, and @#@, between 1 and 128 bytes, starting and ending with an
alphanumeric character. The alphabet excludes every path separator, so an identity can be
used as a file name without escaping. Identities are never normalised, folded, or re-minted:
two identities differing only in case are two identities.

### Measurements and three-valued logic

Every quantity is a @Measurement<T>@ in one of four states: @Known@, @Unknown@,
@Unsupported@, or @Unavailable@. A default-constructed measurement is @Unknown@, never zero.
A constraint evaluates to @Satisfied@, @Violated@, or @Indeterminate@, and the third is not a
synonym for either of the others. Read as satisfied it would fabricate a placement; read as
violated it would hide one.

Everything is an exact integer. There is no floating-point number anywhere in the data model
or the document format. Every arithmetic operation on a capacity, duration, count, or sequence
number reports overflow instead of wrapping.

### Evidence

An evidence snapshot is one reading of the world at one generation, and every record in it
carries a @Provenance@: the identity of the upstream record, the authority that produced it,
the generation of the upstream document, the instant the authority observed the fact, an
optional expiry, and the digest of the upstream document when the caller has it.

Freshness is a property of the record and of the instant the caller says it is being evaluated
at. It is never a property of when this process read the bytes. Stale evidence is refused, not
merged, and a record with no observation time cannot be shown to describe the present.

Evidence collections are:

* @sites@: identity, jurisdiction, and maintenance state.
* @failure_domains@: each domain, its kind, and which domain contains it.
* @domain_assignments@: which site is inside which domain.
* @domain_aliases@: which two domain identities are one physical domain.
* @capacity@: an offer or commitment reference, its site, service class, and reported amount.
* @latency@: a directed measurement between two sites, with the statistic it is expressed over.
* @recovery@: whether a site can host a recovery placement of a class, and the RTO and RPO it
  can meet.
* @compatibility@: whether a service class may run at a site.
* @cost_risk@: reported cost per unit and risk in parts per thousand.

Two records with one identity that disagree are a conflict, never a merge: choosing one of two
readings of one identity is exactly the case where keeping either would be inventing a fact.

### The request

A request carries its own identity and generation, a policy identity and generation, an allow
list and a deny list of sites, a preference list, a freshness policy, and a validity policy.
Each obligation carries a service class, the capacity required at each placement, primary and
recovery placement counts, recovery objectives, jurisdictions, per-obligation allow and deny
lists, separation requirements, latency requirements, and whether two of its placements may
share a site.

A latency requirement names a peer: either another obligation in the same request, or a service
that already runs at a named site. It names a direction, the statistic the bound is expressed
over, the bound itself, and which of this obligation's placements it applies to.

A separation requirement names a group (@All@, @WithinRole@, or @AcrossRoles@), a set of domain
kinds that no pair in that group may share, and optionally specific domains that no pair may
share. A separation requirement that names neither a kind nor a domain is refused: it would
constrain nothing while appearing to.

### The policy

Policy is authored elsewhere. The request names a policy by identity and generation, and the
caller supplies the document; if the two disagree, planning refuses with @conflict@ and names
both sides. That check exists because the failure it prevents is silent: a plan that looks like
it followed the policy the request named, but did not.

Every policy flag resolves a question this boundary cannot answer from evidence, and every one
of them defaults to the reading that claims the least. Nothing defaults to "assume it is fine".
In particular an unreported maintenance state is not operational, and an unrecorded jurisdiction
is not any jurisdiction.

### The plan

A plan carries its identity, its outcome, the request it answered, the per-obligation detail,
the constraint trace, the residual requirements, the tie-break records, an optional structured
refusal, and a freshness envelope.

The outcome is one of three:

* @planned@: every obligation in the request was placed.
* @refused@: a proof that no arrangement satisfies the request as stated.
* @indeterminate@: not a proof of anything. The planner could not decide with the evidence and
  the budget it was given.

Keeping @indeterminate@ separate from @refused@ matters: a caller that reads the two alike will
either retry forever or abandon a placement that exists.

Each placement names its site, its role and index, the capacity required, the exact capacity
references the plan leaned on with the total they evidence and whether any of them is an offer
rather than a commitment, the resolved failure-domain ancestry, and the jurisdiction. Each
latency resolution names the statistic, the measured value, whether it was derived, and the
whole chain of records it rests on.

## How a plan is decided

### Rule order

The rules run in this order, and the plan names the first one that did not pass. The order is
part of the contract rather than an implementation accident: a request with several defects
reports the first one in this order, and the test suite pins it.

| # | Rule token | Question |
| - | ---------- | -------- |
| 1 | @csp.rule.request-bounds@ | is the request within every configured bound and structurally valid? |
| 2 | @csp.rule.snapshot-bounds@ | is the evidence snapshot within every bound and structurally valid? |
| 3 | @csp.rule.policy-reference@ | is the supplied policy the identity and generation the request named? |
| 4 | @csp.rule.domain-structure@ | does containment resolve without a cycle, a depth overflow, or a contradiction? |
| 5 | @csp.rule.site-allow-list@ | is the site on the allow list that applies to this obligation, when it states one? |
| 6 | @csp.rule.site-deny-list@ | is the site on a deny list? |
| 7 | @csp.rule.evidence-freshness@ | does the record carry a usable observation time inside the window? |
| 8 | @csp.rule.jurisdiction@ | is the site's jurisdiction one this obligation allows? |
| 9 | @csp.rule.maintenance-state@ | can the site take a new placement? |
| 10 | @csp.rule.service-compatibility@ | may this service class run here? |
| 11 | @csp.rule.capacity-evidence@ | does the reported capacity reach the requirement? |
| 12 | @csp.rule.recovery-capability@ | for a recovery placement, can the site host one? |
| 13 | @csp.rule.recovery-objective@ | for a recovery placement, does it meet the RTO and RPO? |
| 14 | @csp.rule.colocation@ | may a site the obligation already uses take another placement? |
| 15 | @csp.rule.failure-domain-separation@ | are the required pairs separated over the resolved ancestry? |
| 16 | @csp.rule.latency-bound@ | does every latency requirement hold for this pair? |
| 17 | @csp.rule.selection@ | did the search complete an arrangement for this obligation? |
| 18 | @csp.rule.preference-order@ | which admissible candidate does the preference list put first? |
| 19 | @csp.rule.search-budget@ | did the search exhaust its work budget instead of finishing? |

@csp-cli rules@ prints this list from the library, so a reader of a trace can tell an absent
rule from a rule that passed.

### Candidate ordering and tie-breaks

Candidates are ordered by the request's preference list, which is a strict priority order: the
first objective decides and each later one breaks only the ties the earlier ones left. The
final tie-break is always the site identity in byte order, so a total order always exists even
when no preference can be evaluated at all.

@MinimiseCost@ and @MinimiseRisk@ order sites by the reported value, with sites whose value
nobody reported last. They are never treated as free or as safe, and the plan records the
criterion as @indeterminate@ when not every candidate had a reported value, so a reader can see
how much of the ordering the criterion actually decided. @MaximiseDomainSpread@ orders sites by
how many resolved failure domains they belong to, most first; it is a per-site ordering and the
plan says so rather than claiming to have maximised anything about the chosen set.
@MinimiseSites@ is applied by the search, which tries a site already chosen for the obligation
before a new one when the obligation permits co-location.

The search is a depth-first walk over the candidate order with backtracking, written iteratively
rather than recursively because the number of placements is an externally supplied number. The
first complete assignment it reaches is the answer, and because it tries candidates in
preference order and backtracks only when a choice cannot be completed, that assignment is the
preferred one among those satisfying every hard rule.

### Failure-domain resolution

Failure-domain membership arrives as three separate things: which domains exist and what
contains what, which site is inside which domain, and which domains are two names for one
thing. None of them is usable alone. A separation rule is evaluated against the transitive
closure of containment, because a shared root is a shared failure, and against alias-merged
identities, because two registries naming one power feed twice is the ordinary case rather than
the exotic one.

Two sites that share a domain of a kind the rule names are not independent, however many
distinct leaf names they carry. Two sites that share a domain whose kind nobody published
cannot be shown to be independent, and the rule is left undecided rather than reported as
satisfied. A site with no recorded membership is independent of nothing, because two sites with
no published domains may be one building.

A containment cycle is refused as contradictory. A chain longer than the configured depth is a
bound. Two aliased domains that disagree about their kind or their container are a conflict.
The resolved structure is bounded, so an adversarial snapshot cannot ask for an arbitrarily
large ancestry.

### Latency resolution

A bound is decided from records the fabric authority published. When no record exists the answer
is that nobody knows, not that the path is fast.

A direct measurement of the exact ordered pair settles the bound. A measurement must be at least
as strict as the requirement: a bound over the maximum is satisfied by a peak measurement but a
bound over the 99th percentile is not, because a peak does not bound a tail and a tail does not
bound a peak. Paths are directed; the reverse of a measurement is a different measurement and is
never substituted.

When there is no direct record, a chain of maximum-statistic measurements can still settle the
bound, because the maximum of a sum is at most the sum of the maxima. Only the maximum statistic
may be composed: percentiles do not add, and adding them would invent a number no instrument
produced. The chain is recorded in full, the hop count and the relaxations are bounded, and the
search is a shortest-path computation over non-negative weights, so a cycle in the evidence
neither hangs nor changes the answer. A policy flag turns derivation off entirely.

### Recovery placements

A recovery placement is a site that could take over. It must satisfy the recovery capability and
objective rules, and by default it may not share a site with a primary placement of the same
obligation. This boundary selects the site and stops there. Bringing it up is the recovery
authority's decision, and executing a recovery is not something this library can do.

## Plan identity, digest, and canonical form

The canonical encoding of a value is the compact JSON form produced by this library, with
object keys in byte order and every byte outside printable ASCII escaped, so the encoding is a
pure function of the value and cannot be perturbed by a locale or a terminal.

The plan digest is SHA-256 over the canonical encoding of everything in the plan except its own
identity and digest fields. The identity is then derived from the digest, so two processes that
answer the same question produce plans with equal identity and byte-identical canonical forms.

The plan is a value: the snapshot, the request, and the policy are copied into the call and are
never read afterwards by anyone else, so a caller mutating its own copies cannot change a plan
that was computed from them.

## Freshness, expiry, and revalidation

The envelope records the instant the caller said the world was being evaluated at, the oldest
observation among the evidence the plan actually relied on, the evidence, policy, and request
generations, the instant the plan stops being usable, and the conditions under which it must be
recomputed rather than used. That list is always non-empty: a plan that never needs revalidation
would be a plan that claims the world does not move.

@plan_revalidate@ asks a narrow question: does this plan still hold against this newer snapshot
and policy? It answers @holds@, @broken@, or @undecidable@, and the third is not a synonym for
either of the others. It checks that each placed site still exists, is still in a maintenance
state the policy admits, still evidences the capacity the placement was made against, and is
still compatible; that every separation requirement still holds over the new ancestry; and that
every latency bound still resolves. A generation that moved without any fact changing is
recorded as a condition rather than a break.

## Persistence and recovery

The store is a directory holding a manifest, a lock file, and one record per published plan.
Both the manifest and the records are line-oriented text with an explicit length and an explicit
digest, so a partial write is detectable at the byte level rather than inferred from a parse
failure.

The commit protocol is:

```
validate -> write a staging file beside the record -> write every byte -> flush ->
read it back, decode it, verify length, CRC-32, and SHA-256 -> replace the record atomically ->
write and flush a manifest that references it -> publish
```

The manifest is written last and is what makes a commit visible. A crash before the manifest
lands leaves a record that no manifest references; recovery reports it and never silently
promotes it. A crash during the manifest write leaves the previous manifest, which is still
entirely valid, because the manifest is replaced atomically from a staging file of its own.

The durability claim, stated exactly: on return from a successful commit, the record and the
manifest have been handed to the operating system's flush for those files, and the directory
entry has been flushed where the platform provides such a call. That is a claim about the flush
boundary, not about any particular class of stable media.

Recovery, performed under the store lock when the store is opened:

1. Staging files left by an interrupted commit are removed. The commit had not been published,
   so removing it restores nothing and destroys nothing.
2. The manifest is decoded and its own digest verified. A manifest that does not verify is
   refused: the store does not open rather than truncating through it.
3. Every record the manifest references is read, its size checked against the declared size, and
   its digest checked. A record that fails is interior corruption, and the store refuses to open
   with a hole in it.
4. Records that no manifest references are reported and kept. They may be the durable half of a
   commit that is still in flight.

@compact@ removes records that no committed manifest references and that are strictly older than
the committed generation. A record newer than the committed generation is never removed, so
compaction cannot supersede uncommitted new state.

A commit carries the generation it expected. A mismatch is a refusal naming both generations
with @stale@, and nothing is written.

## Concurrency and lock order

The lock order is @PlanStore@'s own mutex first, then the store's lock file. Nothing takes them
in the other order. No caller code runs while either is held, there are no callbacks in the
library, and no lock is ever taken twice.

The engine holds no locks at all. Its only concurrency is @parallel_for@, used for exactly one
thing: evaluating a per-candidate predicate over a candidate list with a bounded number of
workers. The predicate is a pure function of the candidate and the snapshot, writes only its own
slot, and calls nothing that acquires a lock. Results are assembled in index order after every
worker has been joined, so the answer does not depend on how many workers ran or which finished
first. Workers are always joined, including on the cancellation path; none is ever abandoned.
Cancellation is cooperative and observed between items; a cancelled call returns @cancelled@ and
no plan, and never a partial one.

## Validation performed

Two kinds of evidence appear below. Results measured on the machine that produced this
repository are marked as such: Windows x64, MinGW-w64 GCC 14.2.0, MSVC 19.44, CMake 4.3.2,
Ninja 1.13.2. Results from the continuous integration workflow ran on GitHub-hosted
runners, and the job that produced each one is named. Nothing is projected: every number
and every pass below was executed somewhere, and what has not been executed is listed at
the end rather than implied.

### The test suite

```
cmake -S . -B build/all -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++ \
      -DCSP_BUILD_TESTS=ON -DCSP_BUILD_BENCHMARKS=ON -DCSP_BUILD_CLI=ON -DCSP_BUILD_EXAMPLES=ON
cmake --build build/all
./build/all/tests/csp-tests.exe
```

Release: **129 cases, 17 471 checks, 0 failures**. Debug: the same 129 cases and the same
17 471 checks, 0 failures. The suite was run three times in Release with an identical
result each time. @ctest --test-dir build/all@ reports 5 of 5 passing in 13.3 seconds: four
examples and the suite.

The suite is deliberately not built out of one flavour of case:

| Area | What it establishes |
| ---- | ------------------- |
| values | the identity alphabet, exact-integer overflow, the four measurement states, Kleene logic and De Morgan over all nine pairs, one error token per category |
| documents | a full snapshot round trip, 21 decoder refusals each by category and code, every collection bound tested at the bound and one past it, a plan altered by one byte refused as @integrity@ |
| placement | determinism, seeded ingestion-order independence over all nine evidence collections, and one case each for capacity, maintenance, compatibility, jurisdiction, preferences, policy identity, freshness, and the validation refusal set |
| separation | kind rules against named rules, transitive containment, aliases caught only once declared, a site with no membership never reported as separated, violation outranking doubt, and the structural refusals |
| latency | direct bounds, unknown stays unknown, statistic coverage in both directions, direction, derived maximum chains recorded in full, percentiles never composed, cycles that neither hang nor change the answer |
| adversarial | duplicate identities in all seven identity-keyed collections, capacity at the integer limits, every lowerable bound exercised, 14 truncation offsets, payload flips, declared-length changes, a corrupt manifest, a deleted record, a path-traversal identity, and cancellation |
| property | an independent model that decides the same question from the raw evidence, compared with the planner over 400 seeded fleets in both directions |
| concurrency | byte-identical plans for @worker_threads@ 0, 1, 2, 4 and 8, including the pass that actually splits candidate evaluation across workers; 64 calls from 8 threads; 4 readers times 300 rounds against a writer; concurrent commits |
| persistence | commit, real close, real reopen and load; idempotent recommit against identity reuse; audit; compaction that never removes a record newer than the committed generation |
| revalidation | holds, each broken condition named, undecidable where the evidence is merely absent, expiry, and the structural refusals |
| multiprocess | real second and third OS processes: concurrent commits that stay consistent, a lock refused within its bound, and a store reconstructed between the record write and the manifest write |
| cli | the real @csp-cli@ driven as a child process: exit codes 0, 1, 2 and 3, the digest recomputed independently and compared, and the store round trip through the tool |

Two claims the suite makes explicitly rather than by omission: a cancelled call never
produces a plan, and the uncancelled call with the same inputs does; and an arrangement
that the independent model finds admissible is never refused.

### Adversarial results worth naming

* Truncating a record file at 14 different offsets is refused by both the record decoder
  and the store, each naming the byte-level cause.
* A single flipped payload byte is caught by the CRC-32 in the decoder and by the SHA-256
  in the store; a changed declared length is caught by the length check.
* A corrupt manifest makes the store refuse to open, and the file is left byte-for-byte
  unchanged: the store never truncates through interior corruption.
* A record whose manifest entry has been removed is reported by recovery and never
  adopted, and compaction keeps it because it is newer than the committed generation.
* A record file name containing a path traversal is refused by identity parsing with
  nothing created on disk.
* A capacity at the integer limit with two placements does not wrap; a sum that cannot be
  represented is refused as @out_of_range@ rather than saturating.

### Concurrency and multiprocess

The parallel candidate-evaluation pass is taken when an obligation has a per-site
preference to order by, the candidate count reaches @parallel_threshold@, more than one
worker is allowed, and the whole pass is known to fit the remaining work budget. The
concurrency suite exercises the pass that meets all four conditions and asserts that the
plan, its identity, and even the number of work units consumed are identical to the
single-threaded result.

Two real processes committing to one store concurrently both succeed and the store stays
consistent. A second real process is refused the store lock within its bound and is
accepted once the holder releases. A thread is never described as a process anywhere in
the suite.

### Independent downstream consumer

```
cmake --install build/all --prefix <prefix>
cmake -S examples/consumer -B consumer-build -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
cmake --build consumer-build
./consumer-build/csp-consumer
```

The consumer is a separate project that finds the package through
@find_package(CrossSitePlacement REQUIRED)@, links
@CrossSitePlacement::CrossSitePlacement@, places one obligation, and prints @consumer ok@
with a plan digest. It is configured against the install prefix only and never against
this build tree.

### Continuous integration

The workflow in @.github/workflows/ci.yml@ is the evidence for the configurations that
cannot be reproduced on one machine. It runs seven jobs and every one of them passes on
the commit this release is built from:

| Job | Configuration |
| --- | ------------- |
| Ubuntu / GCC | Release and Debug: build, the whole suite, the synthetic benchmark, a CPack archive |
| Ubuntu / Clang | Release and Debug |
| Ubuntu / GCC / ASan+UBSan | @-DCSP_SANITIZE=address+undefined@ with @UBSAN_OPTIONS=halt_on_error=1@ and @ASAN_OPTIONS=detect_leaks=1@ |
| Windows / MSVC | Release and Debug: build, the whole suite, the synthetic benchmark, a CPack archive |
| Windows / MSVC / AddressSanitizer | @-DCSP_SANITIZE=address@ |
| Installed package / downstream consumer | Ubuntu and Windows: build, install, configure the consumer against the prefix alone, build it, run it |
| Shared library / installed package / downstream consumer | Ubuntu and Windows: @-DCSP_BUILD_SHARED=ON@, build, the whole suite, install, consumer built against the prefix and run against the shared library |

No job sets @timeout-minutes@, and no test carries a CTest @TIMEOUT@ property, so the
matrix has the same rule the local build has: a hang is a defect, not a case to kill.

The shared-library job asserts the thing it names rather than assuming it. It checks that
the shared object is present in the install prefix, runs the consumer with the loader told
where to find it, and then verifies that the consumer really depends on it - @ldd@ on
Linux, @dumpbin /dependents@ on Windows - because a consumer that silently linked a static
copy would run just as happily and would prove nothing.

The POSIX branch of @src/fs_atomic.cpp@ is executed in full by the Linux jobs. They compile
it and then run the whole suite, which performs every store commit, reopen, lock
acquisition and refusal, directory listing, and tree removal the tests describe.

### Not exercised

* **Sanitizers on this machine.** The MinGW-w64 toolchain used here ships neither
  @libasan@ nor @libubsan@: linking @-fsanitize=address@ fails with @cannot find -lasan@,
  reproduced with a two-line probe program. The sanitizer configurations are exercised in
  CI by GCC on Linux and by MSVC on Windows, and by MSVC on this machine; they are not
  exercised here by MinGW.
* **A Linux machine at hand.** Every Linux result in this document comes from the CI jobs
  above. Nothing about Linux was measured on the machine that wrote this repository.
* **The POSIX branch of @fs_atomic.cpp@ on this machine.** It is not compiled on Windows at
  all. It is compiled and exercised by the Linux CI jobs.
* **32-bit and big-endian targets.** Neither has been built or run in this repository's
  history.
* **Real hardware.** No test, benchmark, or claim here describes a physical facility. The
  benchmark numbers are synthetic by construction.

## Benchmarks

@csp-benchmark@ measures completed operations, never submission or enqueue latency. Every
number below is **SYNTHETIC**: generated from a fixed seed on this machine, and describing
no real deployment. No before-and-after comparison is published, because no second
implementation was measured.

```
./build/benchmarks/csp-benchmark --scale=full
```

One completed @Planner::plan@ call, end to end, on a synthetic fleet of the stated size:

| sites | obligations | placements | reps | median ns | min ns | nodes explored |
| ----: | ----------: | ---------: | ---: | --------: | -----: | -------------: |
| 1 000 | 2 | 4 | 11 | 7 508 600 | 5 481 300 | 4 008 |
| 5 000 | 2 | 4 | 7 | 50 860 600 | 43 793 200 | 20 006 |
| 20 000 | 2 | 4 | 3 | 198 820 400 | 196 706 000 | 80 008 |
| 50 000 | 2 | 4 | 3 | 618 518 300 | 594 951 900 | 200 006 |

Durable operations, measured separately and not part of the planning numbers above:

| operation | work | reps | median ns | min ns | bytes |
| --------- | ---- | ---: | --------: | -----: | ----: |
| encode and digest | a plan drafted from a 50 000 site fleet | 11 | 73 900 | 65 000 | 6 779 |
| store commit | distinct plans over a 256 site fleet | 16 | 8 578 900 | 4 020 900 | 110 711 |

The @--scale=small@ ladder (1 000, 5 000, 20 000 sites) is the default and finishes in
seconds. The deterministic columns - sites, obligations, placements, nodes explored, bytes
- are identical across repeated runs; the timings are not, and are reported as measured.

## Platform support and limitations

Supported and exercised:

* Windows x64, MinGW-w64 GCC 14.2.0 and MSVC 19.44, Release and Debug, static and shared, on
  the machine that produced this repository.
* Linux x86-64, GCC 13 and Clang 18, Release and Debug, under AddressSanitizer and
  UndefinedBehaviorSanitizer, static and shared, in continuous integration.
* The Windows shared build uses CMake's automatic export-symbol generation, because the public
  surface is value types and free functions rather than annotated classes. A downstream program
  linked against the installed import library and ran against the installed DLL.

Known limitations, stated rather than implied:

* **The file lock is advisory.** A process that does not go through @FileLock@ can still write
  to a store directory. Every operation in this library goes through it, which is what makes the
  protocol hold between cooperating processes; it is not a defence against a hostile one.
* **A store directory cannot be deleted while a store is open on Windows**, because the lock
  file is opened without delete sharing. Close the store first.
* **The durability boundary is the platform's flush.** @write_file_durable@ hands the bytes to
  the operating system's flush and flushes the directory entry where the platform has such a
  call. It makes no claim about any particular class of stable media, and none is made for it.
* **The POSIX branch of @fs_atomic.cpp@ is not compiled on Windows.** It is written for
  @open@, @flock@, @fsync@, and @rename@, and the Linux CI jobs compile it and run the whole
  suite through it. It has never been run on the machine that produced this repository.
* **The text decoder recurses once per nesting level**, bounded by @max_document_depth@ which
  defaults to 48. Raising that bound far above a few hundred on a build with frame pointers
  could exhaust a default thread stack. The bound is configurable precisely because it is a
  bound, and lowering it is always safe.
* **Capacity is summed, never converted.** This boundary does not interpret units, so it cannot
  tell that two references report the same physical capacity in different ways. It records
  exactly which references it counted, so an over-count introduced upstream is visible in the
  plan rather than hidden by it.
* **Planning is bounded work.** A search that exhausts its budget reports @indeterminate@ with
  @search_exhausted@ set, which is not a proof that no arrangement exists.
* **One compiler diagnostic is suppressed, for one compiler.** GCC's
  @-Wnull-dereference@ rests on @-fdelete-null-pointer-checks@ and is documented to be
  prone to false positives; at @-O3@ it fires inside libstdc++'s own @<streambuf>@ when a
  first-party translation unit uses a stream. The diagnostic is about a system header, so
  there is nothing in first-party code to fix, and the suppression is GCC-only, names one
  diagnostic, and is written where it applies rather than applied across the board. Every
  other warning in the set is an error on every compiler.
* **One compiler false positive shaped some test code.** GCC 13 at @-O3@ reports an
  out-of-bounds @memmove@ inside libstdc++ when a record holding a vector of one-byte
  enumerators is copied into the vector that holds it. The copy was correct; constructing
  the record in place with @emplace_back@ avoids the analysis entirely while keeping every
  warning enabled, so that is what the tests do.

## Relationship to adjacent boundaries

| Boundary | What crosses the line |
| -------- | --------------------- |
| Site registry, site control plane | site identity, jurisdiction, maintenance state, and their provenance |
| Failure-domain registry | domain identity, kind, containment, site membership, and aliases |
| Regional capacity broker, reservation fabric | capacity offer and commitment references and their reported amounts, read only |
| DFI, path and latency authorities | directed measurements between sites, with the statistic and the provenance |
| Recovery and disaster-recovery authorities | whether a site can host a recovery placement of a class, and the objectives it can meet |
| Compatibility registry | whether a service class may run at a site |
| Policy authoring | the policy document a request names by identity and generation |
| Cross-Site Reservation and neighbouring DCCP boundaries | the plan: selected sites, exact evidence references, the constraint trace, residual requirements, and a sealed digest |

Nothing crosses in the other direction. This boundary publishes a plan and records its own
plans in its own store; it does not write to any authority it reads from.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
