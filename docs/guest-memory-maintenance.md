# Guest memory maintenance export

The optional `convex_wasm_udf_memory_maintenance` export has Wasm type
`(i32, i32) -> i32`. It returns the address of a guest-owned result record.
It adds no host imports and does not require a particular Wasmtime revision.
Hosts that do not implement prepared-image sharing can ignore it.
The maintained gate configuration exports it from capability packages and
module-graph base modules. Custom runtime mains and other artifact modes need
not provide it. A host must reject a present export with a different type.

The first argument selects an operation:

| Operation | Second argument | Behavior |
| --- | --- | --- |
| 0 | 0 | Prepare literal layouts, finish ordinary collection and separate prepared storage from subsequent allocation before image capture. Returns no discard ranges. |
| 1 | Host page size | Enumerate currently free allocator payload, with at most 128 ranges and 4,096 visited free blocks. |
| 2 | 0 | Attempt young collection and return empty nursery payload. |
| 3 | Host page size | Enumerate free dynamic GC payload, with at most 128 ranges and 4,096 visited free cells. |
| 4 | 0 | Observe an already empty nursery without advancing collection. |
| 5 | Positive occupied-byte threshold | Check dynamic allocation pressure; collect the nursery if needed, then perform ordinary full collection if pressure remains or young collection defers. Returns collection progress, never discard ranges. |
| 6 | 0 | Trim unused weak-slot chunks at a settled empty-nursery boundary. Returns no discard ranges. |

Operation 0 requires successful preparation of every selected entry, no handler
having started, and no invocation capability. All other operations require
successful operation 0. A successful handler or preparation call establishes a quiescent
guest boundary; a trapped or unsuccessful call does not. An invalid operation,
argument or lifecycle boundary traps. The host must discard the affected Store
after a trap rather than attempting reclamation on partially executed state.
Entry validation failures also end the previous boundary's permission. Runtime
destruction is exclusive with preparation, invocation and maintenance. A repeated
operation 0 before invocation observes the same prepared boundary; it does not
create another region or capture request-warmed state. Failure traps and leaves
the Store unusable, even after an earlier success. Page-size arguments must be
powers of two from 4 KiB through 64 KiB. Wasm i32 arguments and returned offsets
are interpreted as unsigned 32-bit values.

The result is 1,048 bytes, with little-endian unsigned 32-bit fields:

| Byte offset | Meaning |
| --- | --- |
| 0 | Version, currently 3 |
| 4 | Record byte length, 1,048 |
| 8 | Operation echoed from the call |
| 12 | Operation-specific status, defined below |
| 16 | Range count, at most 128 |
| 20 | Number of visited free allocator blocks or GC cells, at most 4,096 |
| 24 | Up to 128 pairs of start and exclusive end offsets |

Only the first `count` range pairs are defined; unused slots grant nothing.

| Operation | Valid statuses | Range and visit counts |
| --- | --- | --- |
| 0 | 0 prepared | Both zero. |
| 1 | 0 complete, 1 partial | Bounded ranges and visited blocks; partial output authorizes only its returned ranges. |
| 2, 4 | 0 empty nursery, 2 deferred, 3 unsupported | Status 0 returns one nonempty range; other statuses return none. Visits are zero. |
| 3 | 0 complete, 1 partial, 2 deferred, 3 unsupported | Complete/partial output contains bounded ranges and visited cells. Deferred/unsupported counts are zero. |
| 5 | 0 unnecessary, 4 young collection performed, 5 full collection performed | Both zero; these statuses grant no free-space authority. |
| 6 | 0 trimmed, 2 deferred, 3 unsupported | Both zero. |

Nursery payload may need inward alignment to host pages; allocator and GC ranges
are already aligned. The host validates record bounds, version, operation,
status, counts, within-owner overlap and memory bounds. Before discarding any
payload, also reject overlaps between allocator, GC and the entire nursery
range, including any nursery prefix the host chooses to retain.

Deferred collection makes no collector progress. In particular, repeated young
collections must yield to ordinary old-generation GC when survivors approach its
start threshold. Do not retry operation 2 in a loop to force success: allow
ordinary GC or restore/dispose the instance. Operation 5 makes one guarded young
attempt, followed by ordinary full collection when needed. If the nursery is
already empty, it avoids repeating root/weak processing and proceeds to full
collection for remaining occupied pressure. The pressure estimate includes
dynamic occupied cells and their external storage, plus positive aggregate
external growth on prepared owners; it is not a physical-memory measurement.

In the maintained wasm32 runtime, Hades is single-threaded. Version 3 preparation
finishes collection and any pending compactee before recording prepared storage.
Later ordinary full collections may leave incremental work for a subsequent
guest call; range observers defer when that work prevents safe export. No
collector work executes outside a guest call. The single-threaded Emscripten
finalizer executor runs tasks inline. Collector worklists, allocator metadata
and native buffers remain in linear memory. Capture preserves them, and restoration
must reconstruct the same function-table indices for collector callbacks and
finalizers. This does not certify arbitrary native or concurrent runtime state.

Versions 1 and 2 support only operations 0–2. Version 1 tied operation 0 to nursery reclamation. Its successful result contains
one nonempty range; deferred/unsupported results contain none and do not certify
an image. Version 2 preparation returns no ranges and permits live nursery or
pending incremental work in the captured image; it does not separate allocation
regions. Operations 1 and 2 retain their historical semantics in version 3.
Hosts must retain each accepted version's behavior and reject unknown versions
or version changes within one Store. A restored Store can discover the version
using operation 1, which every version supports. Calling an unknown operation
and recovering from its trap is not compatibility negotiation. Hosts that ignore
the optional export can continue ordinary execution.

Copy the result before another maintenance call overwrites its storage. Keep the
Store exclusively borrowed through enumeration and discard, with no guest
allocation, collection or other concurrent access. Operations 1, 3 and 4 do not
allocate or collect, so their freshly copied results can coexist. Collection
and weak-slot trimming must precede those observers: both can invalidate earlier
free-space evidence. Running a handler or preparation also invalidates previous
range authority. The result does not pin memory.

Collection may evacuate survivors and invoke native finalizers. Retain their host
resources until it completes and enforce memory limits during cleanup, not just
during handlers. Allocator enumeration has explicit work/output bounds; collection
has ordinary GC cost and is not a fixed-latency operation. Collection, enumeration
and discard remain within the original invocation's CPU/fuel/deadline authority;
the guest export never replenishes those budgets.
Discard only backing that the host actually owns and has charged. Keep the
active charge through cleanup and transfer the remaining charge to an idle slot
only afterward. Failed or partial host mapping changes must prevent reuse.

This export supplies guest-side preparation and reclamation only. A complete
image also requires compatible native graph reconstruction, Store-owned function
and table references, mutable globals, stack limits, host state and source/config
authority. A linear-memory copy alone is not a reusable Store snapshot. See
[runtime reclamation primitives](memory-reclamation.md) for GC and allocator
ownership contracts.
