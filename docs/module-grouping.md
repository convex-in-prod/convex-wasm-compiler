# Module grouping and local initialization measurements

Runtime grouping determines which entries can share an initialized guest heap.
Physical compilation shards determine which unchanged code can be reused after
an edit. A dependency can remain a separate compilation shard with one consuming
runtime group. Grouping does not share mutable heaps between instances, remove
module side effects, or prepare replacement instances before deployment activation.

## Default grouping

Project module-graph builds group entries automatically from their authenticated
emitted dependency closures. Each module's source-byte cost is rounded up to
4 KiB. The deterministic planner considers sparse dependency-occurrence chains
and a coarse cost-order chain, discounts widely shared modules when ordering
merges, and merges only when the union cost is at most 1.5 times every member's
standalone cost. Each group must also fit the guest's 1,024-logical-unit limit,
including one publication unit per entry. A single entry exceeding this bound
fails before compilation.

There is no configured group count, equal-size requirement, timing calibration
or saved previous partition. The algorithm does not execute guest code or call
a profiler. It derives unequal groups from current dependencies and uses stable
path order for ties. Small source edits generally retain the same relationships;
changes at cost thresholds or to dependencies can change membership. Source size
is a repeatable cost proxy, not a prediction or bound on initialization time.

The shared `planConvexWasmOfficialOutputEntryGroups({ graphSession, entryPaths })`
API authenticates emitted modules and applies this build policy. Consumers with
a separate deployment builder should use it to construct their cohort schedule.
The lower-level `planConvexWasmEntryGroups` function operates on complete dependency
closures and positive integer costs. Its result includes memberships, modeled
costs, a partition fingerprint and candidate/merge counts; it does not claim an
optimal partition.

`buildConvexWasmProjectPackage` also accepts explicit `entryGroups` for compiler
integration and controlled comparisons. They must cover every selected entry
exactly once. There is no user-facing policy selector. The low-level schedule
reader retains the old lexical format for existing packages, and legacy monolithic
capability packages retain their eight-entry bound. Module-graph grouping uses
the logical-unit bound instead of an arbitrary entry-count limit.

Grouping and physical sharding are separate. Keeping a component in its own
physical shard with one consuming runtime group preserves reusable native code
when an entry changes. More interchangeable entries within a group can reduce
fragmented runtime capacity, but grouping alone does not initialize instances
before traffic or choose a prepared-pool size.

Modules with multiple static imports to distinct targets use stable dependency tokens and
canonical declaration order before identifier minification. Imported function specialization
also breaks equal-benefit ties by local binding name. Source evaluation order is held separately
in authenticated `import-initialization` aliases in the dependency selector. These aliases form
a complete, unique permutation of the static bindings. The runtime initializes each dependency
in source order and immediately assigns its namespace, preserving side effects and partially
initialized bindings through cycles. When dependency native-symbol locators stay unchanged,
import order and emitted dependency filenames can change without recompiling an unchanged
module body. Source bindings and selector topology still change with evaluation order.
Repeated static targets retain their ordinary lowering; dynamic imports retain their deferred
evaluation. Source-less or equal-membership chunks still use occurrence-based binding paths
to distinguish their native-symbol locators.

## Measure actual preparation

The optional Cargo `capability-replay` feature provides the
`convex-wasm-graph-initialization` binary. The current measurement runner requires
Linux for CPU affinity, thread CPU time and process RSS. These measurement-tool
requirements do not change portable Core Wasm execution requirements.

Use `scripts/prepare-convex-wasm-graph-initialization.mjs CONFIG.json INPUT.json`
to authenticate retained module-graph packages and create the runner input. The
configuration supplies `cacheRoot`, `graphs`, the local initialization environment,
fuel, epoch-poll interval, repetitions, CPU and preparation mode. Each requested
graph names its manifest hash and entries with `name` and `selectorHex`. Selectors
must occur in the verified graph. Keep application inputs and configuration out
of this repository. Native AOT must match the runner's engine identity.

`preparationMode: "allEntries"` prepares every listed entry in each fresh Store;
`"eachEntry"` uses a fresh Store for each entry. Both recheck the prepared entries.
Neither executes handlers. AOT loading, instantiation, native constructors and
first preparation are reported separately. Environment reads are retained by
name. Ordinary handler GC reporting is not an initialization measurement.

`preparationMode: "validateReset"` requires an instrumented graph and validates
the guest failure/reset lifecycle. It prepares and rechecks every selected entry,
supplies invocation authority to preparation, requires rejection status 68, then
replaces only host invocation state. It prepares every entry in reverse order in
the same Store and requires an identical initializer inventory, followed by cached
rechecks. This mode emits `resetValidationComplete` rather than readiness results
and cannot be combined with pool scenarios. Its two initializations must fit in
the diagnostic trace buffer.

An optional `scenarios` array specifies complete prepared pools:

```json
{
  "name": "two-instance-pool",
  "workerCpus": [0, 2],
  "instances": [{ "graph": "graph-name", "count": 2 }]
}
```

All Stores remain alive until the pool is ready. The runner reports elapsed time,
summed preparation CPU, linear memory and sampled process RSS before rechecks.
Use the same worker budget across policies. Equal instance counts do not imply
equal capacity for a particular request distribution. RSS includes loaded code
and host allocator state; linear memory is not the reachable JS heap.

## Optional logical initializer trace

For a local diagnostic package, add
`-DCONVEX_WASM_LOCAL_INITIALIZATION_TRACE=1` to `runtime.mainCompileFlags`.
The flag is authenticated in the bridge build inputs. Ordinary builds contain
neither trace storage nor diagnostic exports. The diagnostic must not be treated
as an uninstrumented performance candidate.

Set `initializationTrace: true` in the measurement configuration. A requested
graph may override this default, allowing a balanced traced/control comparison
in one process. The runner rejects a missing diagnostic export when requested,
or an instrumented package described as uninstrumented.

The trace uses a fixed native buffer and WASI monotonic/thread CPU clocks. It does
not create JS values or traverse the JS heap. Buffer exhaustion, invalid nesting
and backward clocks fail the diagnostic explicitly. Records include parent and
logical-unit slot, inclusive/exclusive time, and cumulative GC/heap snapshots.
Kinds are runtime creation (1), runtime support (2), logical module (3), entry
publication (4), intrinsic validation (5), application evaluation (6), and guest
bridge installation (7). Read module-slot identities from the corresponding
authenticated compiler descriptor; they are not physical Wasm artifact indexes.

Exclusive time subtracts immediate child intervals. To price a logical module,
include its evaluation, validation and other local work while excluding nested
module initialization. Do not sum overlapping inclusive measurements or add GC
time again: collection is already inside execution time. Current heap occupancy
includes objects that have not been collected and is not a reachable-object census.

The runner verifies that prepared-entry rechecks add no initializer trace records.
Measure whole-group tracing overhead against the matching uninstrumented package,
and keep calibration runs separate from subsequent policy comparisons.
