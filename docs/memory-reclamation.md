# Runtime memory reclamation primitives

The runtime archives let an embedder prepare ordinary literal layouts, separate
prepared allocation storage, and identify memory that can be discarded after
ordinary reclamation. These are internal C interfaces, not a
host memory-accounting policy or permission to restore arbitrary live objects.
The application bridge and host lifecycle must establish their preconditions.

## Prepared literal layouts

Static Hermes emits sorted ordinary-object shape indexes from the actual lowered
instructions. Typed allocations and unused slots in retained literal tables are
excluded. The existing Static Hermes ABI descriptor binds the new unit fields;
generated units and runtime archives must agree.

`_sh_prepare_literal_layouts` operates on registered units during exclusive,
request-independent preparation. It constructs eligible classes without invoking
application functions and roots them in long-lived GC-managed storage. Dictionary
layouts are excluded. The storage uses normal write barriers and full-GC tracing;
neither its address nor the classes' addresses are assumed to remain fixed.
Property maps are prepared after class transitions, in descending property-count
order across all units: initializing a child's missing map can itself transfer
the parent's map. Repeated calls rebuild missing maps too. Later ordinary runtime
operations can still transfer maps; preparation does not freeze these structures.

Repeated successful calls are valid, including after additional units initialize.
A reported preparation failure requires discarding the partially prepared runtime.
Preparation is an optional embedder operation, not eager work added to every
ordinary application execution.

## Prepared allocation storage

`_sh_begin_prepared_heap` completes ordinary collection and records the existing
normal and jumbo segments in the collector. Subsequent allocations cannot use
holes in prepared segments, and compaction cannot select prepared normal
segments. Prepared objects still undergo ordinary whole-heap tracing, sweeping,
weak-reference processing and finalization. They are not permanently rooted.
When a prepared jumbo segment dies, its address loses prepared ownership before
the native allocator can reuse it. Ordinary write barriers and dirty-card clearing
remain in effect; there is no additional prepared-to-dynamic remembered set.

Call once after request-independent preparation, with exclusive mutator access.
The operation requires nonconcurrent Hades; unsupported collectors return false.
`_sh_prepared_heap_dynamic_bytes` then reports occupied dynamic cells, their
external allocations, and positive aggregate external-allocation growth on
prepared owners above their preparation baseline. Releasing a prepared owner's
buffer cannot hide external storage owned by a dynamic object. This constant-time
value selects collection pressure; it is not a measurement of live survivors,
resident pages or the host's memory charge.

`_sh_dynamic_free_payload` enumerates free dynamic cells after collection has
settled. It excludes free-cell headers, partial pages, prepared holes and pending
compaction storage. The fixed output holds at most 128 ranges, and enumeration
visits at most the caller's limit of 4,096 cells. A partial result grants exactly
its returned ranges. A deferred result grants none and advances no collection.
Do not allocate, collect or mutate the free lists before discarding those ranges.

`_sh_trim_unused_weak_slots` removes entirely unused slot chunks without moving
occupied slots. Containers invalidate their incremental root history before
deletion or reuse; the next nursery visit scans all occupied slots. Full major
and compaction visits always remain complete. Call only at an exclusive boundary
with settled collection, before exporting any native free payload.

## Empty young-generation payload

`_sh_try_reclaim_young_generation` retains ordinary survivor, weak-reference and
native-finalizer processing. It does not start an old-generation collection.
Pending old-generation work, compaction, nursery promotion or worst-case survivor
pressure reaching the old-generation start threshold produces a deferred outcome;
a collector without this facility reports unsupported. These outcomes return no
discardable range. Repeated young-only calls must not postpone necessary old
collection indefinitely. Deferred calls make no collector progress: the caller
must permit ordinary collection or restore/dispose instead of retrying in a loop.
Normal allocation-pressure collection is unchanged.

A successful result describes nursery payload only, excluding collector metadata.
It may require inward alignment to the host page size. Call outside guest
execution with exclusive runtime access; do not resume allocation or collection
before the host finishes discarding the returned range. Host resources referenced
by finalizers must remain available while collection runs. The operation can
allocate while evacuating survivors, so its own work needs metering and memory
admission. An invocation budget must not be replenished by cleanup. This is not
a fixed work or latency bound: it traces roots and dirty cards, evacuates all
survivors, and runs native finalizers. A concurrent Hades runtime can also wait
for the background collector's current marking or sweeping step to yield its
mutex before reporting deferred. Do not call it from a finalizer or GC callback.

`_sh_empty_young_payload` applies the same ownership checks to an already empty
nursery without running collection. An embedder can keep a reusable prefix and
discard only the tail; this never grants authority over an occupied nursery.

## Native allocator payload

`convex_wasm_allocator_free_payload` enumerates whole pages inside current free
dlmalloc payload. It visits sufficiently large free bins, the designated
remainder and the top chunk, rather than every allocated block. Tree links,
boundary tags and footer space remain outside the returned ranges. Its fixed
128-range output and caller-supplied visit limit bound work; a partial result
authorizes only the ranges returned. Invalid arguments or allocator invariants
trap. The allocator is the pinned, single-threaded PIC system-library variant.

The caller supplies live output storage and a power-of-two host page size between
4 KiB and 64 KiB. Allocation, collection and allocator mutation must remain
quiescent from enumeration through discard. The output does not pin free storage;
only proven nonallocating observers may run before discard. Allocation, collection
or weak-slot trimming invalidates earlier ranges. Ranges are not sorted;
callers must not infer address order from bin traversal. Collection may finalize
native buffers, so enumeration must be repeated afterward if their newly freed
storage is needed.

The host must intersect returned ranges with its actual private backing before
granting any physical-memory credit. Free virtual capacity is not released RAM.
Discard failures must preserve conservative charges and prevent unsafe reuse.

The gate builds `libconvex_wasm_allocator.a` separately using the pinned SDK's
allocator build flags and clean system-library environment. It includes the
matching `sbrk` implementation; gate link flags disable automatic selection of a
second SDK allocator. The builder uses the pinned LLVM tools and frozen sysroot
cache, fails if prerequisites are missing, and maps source debug paths to generic
names. It never replaces a shared SDK cache file.

Gate freshness binds the extension, interface, builder, allocator sources, SDK
driver/settings, Python tool sources, compiler/archive tools, headers and archive
bytes. Setup stages its own output before authentication and publishes the receipt
last; changed inputs during the build reject publication. The builder and SDK
driver read Python sources using an empty private bytecode-cache path, so stale
shared bytecode cannot substitute for the authenticated source. Gate-config creation
and verification also require the current receipt. Artifact construction then
authenticates and stages this archive through the normal runtime-archive inputs.
No runtime-specific host import or Wasmtime revision is required by these
primitives.

## Guest maintenance protocol

The application bridge exports `convex_wasm_udf_memory_maintenance(operation,
argument)`. Version 3 retains the fixed 1,048-byte result envelope: six little-endian
32-bit header words (version, length, operation, status, range count, visited count)
followed by capacity for 128 pairs of 32-bit start/end offsets. Unused range slots
have no authority. The bridge requires a successful quiescent boundary and an
already certified prepared image for operations other than preparation.

| Operation | Argument | Result |
| --- | --- | --- |
| 0 | Zero | Prepare layouts and separate prepared storage; no discard ranges. |
| 1 | Host page size | Native allocator free payload. |
| 2 | Zero | Guarded young collection and empty-nursery payload. |
| 3 | Host page size | Collector-owned dynamic free payload. |
| 4 | Zero | Already-empty nursery payload, without collection. |
| 5 | Positive occupied-byte threshold | No collection needed (status 0), young collection sufficient (4), or ordinary full collection performed (5); no ranges. |
| 6 | Zero | Trim unused weak slots at a settled empty-nursery boundary (status 0), deferred (2), or unsupported (3); no ranges. |

Payload statuses are complete (0), partial (1), deferred (2), and unsupported (3),
where applicable. Collection progress never supplies discard authority. Full
collection can leave follow-up work pending, so callers must reacquire ranges and
respect deferred exports afterward. Pressure collection skips a redundant young
pass when the nursery is already empty; status 4 reports a collection that
actually ran. Preparation may be repeated before the first
invocation to observe the same certified boundary; it cannot capture warmed
request state or redefine prepared storage.

Versions 1 and 2 support only operations 0–2. Version 1 preparation returns an
empty-nursery range; version 2 certifies the image without granting discard
authority. Hosts must discover a guest's version through an older supported
operation before issuing version-3 operations. All maintenance consumes the
current invocation's execution and memory allowances, including finalizers;
cleanup must not replenish either allowance.
