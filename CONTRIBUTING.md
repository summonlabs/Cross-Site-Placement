# Contributing

Cross-Site Placement is a decision authority: a defect here is a wrong answer about where
an obligation may go, or a refusal that hides a placement that exists. Contributions are
therefore judged first on whether they preserve the invariants below, and only then on
style.

## Build and test

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Useful variants:

```
# Debug, with assertions and no optimisation
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
ctest --test-dir build-debug --output-on-failure

# AddressSanitizer and UndefinedBehaviorSanitizer, where the toolchain has them
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCSP_SANITIZE=address+undefined
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure

# Benchmarks: completed operations only, small scale in seconds
cmake --build build --target csp_benchmark
./build/benchmarks/csp-benchmark --scale=small
```

Warnings are errors by default. A first-party warning is a defect: fix it rather than
suppressing it, and add a suppression only with a comment saying which defect it cannot
describe.

There is no timeout anywhere in this project, deliberately, and adding one is a rejected
change. The harness has no watchdog, CTest targets carry no TIMEOUT property, and CI jobs
set no `timeout-minutes`. A hanging test is a defect to diagnose; a suite that kills it
reports the defect as a pass.

## Invariants a change must not weaken

1. **A plan is a proposal, not an effect.** Nothing in this library reserves, consumes,
   commits, installs, or mutates another authority's state. Capacity references are read
   and recorded, never written. A change that lets planning consume capacity is the wrong
   change.

2. **Zero is not unknown.** A default-constructed `Measurement` is `Unknown`. A quantity
   nobody reported is never read as zero, and a comparison against a measurement nobody
   made is indeterminate rather than satisfied.

3. **Doubt is never an acceptance.** A candidate that cannot be decided is
   indeterminate. A refusal is a proof that no arrangement exists; an indeterminate
   result is the absence of one. Collapsing either into the other changes the meaning of
   every answer this boundary gives.

4. **Admissibility is separate from preference.** A preference orders candidates that are
   already admissible. It never admits one a hard rule refused, and it never refuses one
   that every hard rule passed.

5. **Ordering is part of the contract.** Candidates are ordered by a total order with a
   documented tie-break whose last resort is the site identity. Equivalent logical inputs
   produce byte-identical plans whatever order they were assembled in. Nothing in the
   deterministic path may depend on a hash iteration, a pointer value, a clock reading, a
   locale, or how many workers happened to run.

6. **Rule precedence is part of the contract.** The rules run in the order documented in
   `README.md`, and the plan names the first rule that did not pass. Reordering the rules
   changes which refusal a request with two defects reports, so it is a behavioural change
   and needs a case that pins it.

7. **Failure independence is decided over the resolved ancestry.** Separation is evaluated
   against transitive containment and alias-merged identities, never against leaf names.
   Two sites sharing a domain of a kind the rule names are not independent; two sites
   sharing a domain whose kind nobody published are not independent either, and the rule is
   left undecided rather than answered.

8. **Consumed evidence keeps its provenance.** Every fact used carries the identity of the
   upstream record, the authority, and the generation it was read at. Freshness is
   evaluated against the instant the caller supplies; this library never reads a clock.
   Network measurements are never invented and never derived except from an explicit chain
   of maximum-statistic records, which the plan records in full.

9. **The decoder is the trust boundary.** Persisted and textual input is parsed by code
   that never reads past its buffer, never allocates before a declared count has been
   checked against both its bound and the bytes that remain, refuses unknown fields rather
   than dropping them, and reports a structured status instead of throwing.

10. **Nothing unverified is published.** A commit writes a staging file, flushes it, reads
    it back, verifies it, replaces the record in one atomic step, and only then writes and
    flushes the manifest that makes the commit visible. A refusal leaves the previous state
    exactly as it was. Interior corruption is refused, never truncated through.

11. **Stale authority is refused, not merged.** A commit carries the generation it
    expected; a mismatch is a refusal naming both generations. A lock is never waited for
    without a bound.

12. **No lock is held while user code runs, and no lock is taken twice.** The lock order is
    `PlanStore` mutex, then the store lock file. Nothing takes them in the other order, and
    the parallel candidate evaluation shares no mutable state at all.

13. **Exact integers only.** Capacity, durations, generations, and counts are integers.
    Every operation that can overflow reports it. There is no floating-point number
    anywhere in the data model or the document format.

14. **Bounds are checked before allocation, and every bound is configurable.** A bound that
    cannot be lowered cannot be tested.

15. **No telemetry.** Nothing is reported anywhere except where the caller asked for it,
    and nothing leaves the process.

## Tests

The suite is the evidence for the guarantees, so a change in behaviour is a change in
tests:

* Add a case that fails before the change and passes after it. A defect fix without a case
  that reproduces the defect is incomplete.
* Prefer a case that pins a property - an invariant, a round trip, a refusal - over one
  that pins an incidental value.
* Assert the refusal: the error category, and the code a caller can act on. A case that
  only checks `!result.has_value()` does not say why the answer is no.
* Where a rule can be modelled independently, model it in `tests/test_property.cpp` and
  compare. A model that calls the engine proves nothing.
* Randomized cases use `csp_test::SeededRandom` and name their seed in the failure detail,
  so a failure is reproducible from the seed alone.
* Multiprocess claims belong in `tests/test_multiprocess.cpp` and must use real processes
  through `tests/helper/csp_multiprocess_helper.cpp`. A thread is not a process, and a
  thread case must not be described as if it were one.
* Concurrency claims belong in `tests/test_concurrency.cpp` and must assert that the
  parallel answer is byte-identical to the single-threaded one, not merely that it did not
  crash.

## Style

* C++20, no extensions, no third-party dependencies.
* Every file starts with the copyright line and the SPDX identifier
  (`// SPDX-License-Identifier: Apache-2.0`).
* Comments explain why a thing is the way it is, at the point where the reasoning is
  non-obvious. Comments that restate the code are noise; comments that record a decision
  are the point.
* Public headers document the contract, including what a caller must not do and which
  error a refusal produces.
* Keep the diff focused: one defect, one change, one test.

## Submitting

1. Build and run the suite in Release and Debug, and under AddressSanitizer or the
   platform's checker if the change touches parsing, persistence, or concurrency.
2. Describe what the change makes true that was not true before, and which case proves it.
3. Do not include generated artefacts, build trees, benchmark output, install prefixes, or
   editor state.
4. Contributions are accepted under the Apache License 2.0, as stated in `LICENSE`, with
   no additional terms. No contributor licence agreement is required, and no co-author
   trailers are used.

## Reporting a defect

A useful report contains the operation, the exact request, snapshot, and policy (or the
seed that produced them), the observed outcome, and what the documented behaviour is. If
the defect is in durable state, keep the store directory: `csp-cli store --dir <path>
audit` reports what the strict reader saw, and the manifest and record files are readable
text.
