# Runtime memory reclamation primitives

The runtime archives provide two distinct operations for an embedder retaining a
prepared guest: prepare ordinary literal layouts, and identify memory that can
be discarded after ordinary reclamation. These are internal C interfaces, not a
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
quiescent from enumeration through discard. The output does not pin free storage
and does not remain valid across another guest call. Ranges are not sorted;
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
