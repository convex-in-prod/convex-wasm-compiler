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
| 0 | 0 | Prepare ordinary literal layouts, perform full collection, then obtain empty nursery payload for image capture. |
| 1 | Host page size | Enumerate currently free allocator payload, with at most 128 ranges and 4,096 visited free blocks. |
| 2 | 0 | Attempt young collection and return empty nursery payload. |

Operation 0 requires successful preparation of every selected entry, no handler
having started, and no invocation capability. Operations 1 and 2 require successful
operation 0. A successful handler or preparation call establishes a quiescent
guest boundary; a trapped or unsuccessful call does not. An invalid operation,
argument or lifecycle boundary traps. The host must discard the affected Store
after a trap rather than attempting reclamation on partially executed state.
Entry validation failures also end the previous boundary's permission. Runtime
destruction is exclusive with preparation, invocation and maintenance. A repeated
operation 0 replaces its previous preparation result; deferred or unsupported
preparation leaves no image certification, even after an earlier success.

The result is 1,048 bytes, with little-endian unsigned 32-bit fields:

| Byte offset | Meaning |
| --- | --- |
| 0 | Version, currently 1 |
| 4 | Record byte length, 1,048 |
| 8 | Operation echoed from the call |
| 12 | Status: 0 complete, 1 partial, 2 deferred, 3 unsupported |
| 16 | Range count, at most 128 |
| 20 | Number of visited free allocator blocks, at most 4,096 |
| 24 | Up to 128 pairs of start and exclusive end offsets |

Only the first `count` range pairs are defined. Status 1 is valid only for
operation 1 and grants authority for exactly the returned ranges. Status 2 or 3
is valid for operations 0 and 2 and grants no range authority. Successful nursery
operations return one nonempty range and zero visited allocator blocks. Nursery
payload may need inward alignment to host pages; allocator ranges are already
aligned. The host validates the record bounds, version, operation, status,
counts, non-overlapping ranges and memory bounds before using any range.
After collection, validate that freshly enumerated native-free ranges are
disjoint from the saved nursery range before discarding either set.

Deferred collection makes no collector progress. In particular, repeated young
collections must yield to ordinary old-generation GC when survivors approach its
start threshold. Do not retry operation 2 in a loop to force success: allow
ordinary GC or restore/dispose the instance. Operation 0 can also defer, even
after its full collection; no image is ready from that result.

Copy the result before another maintenance call overwrites its storage. Keep the
Store exclusively borrowed through enumeration and discard, with no guest
allocation, collection or other concurrent access. Operation 1 does not allocate
or collect, so it may follow operation 2 before the host discards the saved empty
nursery range. Running a handler, preparation or another collection invalidates
previous range authority. The result does not pin memory.

Collection may evacuate survivors and invoke native finalizers. Retain their host
resources until it completes and enforce memory limits during cleanup, not just
during handlers. Allocator enumeration has explicit work/output bounds; collection
has ordinary GC cost and is not a fixed-latency operation. The host owns one
metered cleanup allowance across collection,
enumeration and discard; the guest export never replenishes fuel or deadlines.
Discard only backing that the host actually owns and has charged. Keep the
active charge through cleanup and transfer the remaining charge to an idle slot
only afterward. Failed or partial host mapping changes must prevent reuse.

This export supplies guest-side preparation and reclamation only. A complete
image also requires compatible native graph reconstruction, Store-owned function
and table references, mutable globals, stack limits, host state and source/config
authority. A linear-memory copy alone is not a reusable Store snapshot. See
[runtime reclamation primitives](memory-reclamation.md) for GC and allocator
ownership contracts.
