# VoidNet Distributed K/V Store Design

## Overview

A globally distributed key-value store built on VoidNet's zero-copy XDP network stack and shared-nothing busy-loop runtime. Designed as the foundational data layer for a broader infrastructure suite including a CDN, execution fabric, and global queue.

The system prioritizes:
- Ultra-low latency through kernel bypass (XDP + io_uring + direct I/O)
- Flexible consistency (per-namespace, not per-operation)
- Self-optimizing data placement via access-pattern-driven migration
- Operational simplicity through uniform mechanisms (every component uses the same Raft + SWIM machinery)

## Architecture Overview

```
                        Client
                          |
                    [Any Node] ──── DSR ────→ [Owner Node] ──→ Client
                          |                        |
                    ┌─────┴─────┐            ┌─────┴─────┐
                    │  Routing  │            │  Storage   │
                    │  Layer    │            │  Engine    │
                    │           │            │            │
                    │ Shard Map │            │ WAL        │
                    │ (cached)  │            │ Memtable   │
                    │           │            │ LSM (keys) │
                    └───────────┘            │ VLog (vals)│
                                             └────────────┘
```

### System Layers

1. **Client Protocol Layer** — binary protocol over QUIC (performance) + HTTP REST (accessibility)
2. **Routing Layer** — any-node ingress, shard-based forwarding, DSR responses
3. **Cluster Layer** — SWIM membership, consistent hashing, ephemeral Raft groups
4. **Metadata Layer** — `_catalog` namespace for authoritative config
5. **Storage Engine** — WiscKey-style hybrid LSM + value log with direct I/O

## Cluster Architecture

### Membership: SWIM Protocol

All cluster membership is managed via SWIM (Scalable Weakly-consistent Infection-style Membership). Every node maintains a local membership list and propagates changes via infection-style gossip.

- Sub-second failure detection
- O(log N) convergence
- No single point of failure
- Scales to hundreds/thousands of nodes
- Heartbeats and protocol messages use QUIC datagrams (unreliable, no head-of-line blocking)

### Consistent Hash Ring

The hash ring is a pure function of the SWIM membership view. Every node computes it locally and deterministically — no coordination required.

- Virtual nodes for balanced distribution
- Ring determines shard→node assignment for eventually consistent namespaces
- Ring provides *intent* for linearizable namespaces (see below)
- Ring recomputation is local and instant on membership change

### Inter-Node Communication: QUIC with Null-Cipher Mode

All inter-node communication uses QUIC:
- Multiplexed streams for replication and data transfer
- Datagrams for SWIM protocol messages
- Connection migration for rolling upgrades

**Intra-cluster:** null-cipher mode (no TLS encryption overhead). A shared cluster secret or HMAC on the handshake prevents accidental cross-cluster connections or rogue nodes. Per-packet encryption is skipped.

**Cross-region (public internet):** full TLS 1.3 encryption.

This is a non-RFC-compliant QUIC mode, but we own the stack and compliance only matters for external interop.

## Consistency Model

Consistency is configured **per-namespace**, not per-operation. A namespace's consistency level is set at creation and determines its entire replication and coordination strategy.

### Eventually Consistent Namespaces

- Hash ring is directly authoritative for replica placement
- Any replica accepts writes immediately
- Async replication ships WAL entries to other replicas
- Conflict resolution: last-writer-wins (vector clocks as future extension)
- SWIM membership changes take effect immediately
- Ideal for: CDN cache, session state, non-critical metadata

### Linearizable Namespaces

- Ephemeral Raft group per namespace manages consensus
- Writes go through Raft leader, committed on quorum acknowledgment
- Strong reads go to leader (lease-based or quorum verified)
- Stale reads optionally served by any replica
- Ideal for: queues, coordination, counters, authoritative state

### The Two-Layer Model: SWIM Proposes, Raft Disposes

For linearizable namespaces, the consistent hash ring is the *intent layer* and the Raft group is the *commitment layer*:

| Aspect | Eventually Consistent | Linearizable |
|---|---|---|
| Membership authority | Hash ring (directly) | Raft group (self-managed) |
| Ring change effect | Immediate | Proposal to Raft leader |
| Failure recovery | Automatic, instant | Controlled, sequential |
| Partition behavior | Both sides serve | Only quorum side serves |
| Total loss recovery | Hash ring recomputes | Timeout + resurrection |

**How ring changes flow for linearizable namespaces:**

1. SWIM detects a membership change (node join/leave/failure)
2. Every node recomputes the hash ring locally
3. The ring now says the Raft group membership *should* change
4. The Raft leader proposes a configuration change through Raft consensus
5. Joint consensus ensures both old and new configurations agree
6. Only after commitment does the new membership take effect
7. State transfer (snapshot + log) brings new members up to date

**Why this is safe during network partitions:**

A partitioned node sees other nodes as dead via SWIM. It recomputes the ring and concludes it should be the sole owner. But it cannot act on this — changing Raft group membership requires committing through Raft, and a single partitioned node cannot reach quorum. It is stuck, which is correct. The quorum side continues serving. When the partition heals, the stuck node rejoins.

**Total group failure (all Raft members lost):**

If a Raft group has been unreachable for longer than a conservative timeout (e.g., 10x SWIM failure detection window), surviving cluster nodes can form a new group based on the hash ring. Committed-but-unreplicated data from the dead group is lost. An operator override allows faster recovery. This is rare enough to tolerate manual intervention.

## Metadata: The `_catalog` Namespace

Namespace metadata (what namespaces exist, their consistency level, replication factor, shard map) is too important for gossip alone. Getting it wrong means serving data under the wrong consistency guarantees — a silent correctness violation.

**Solution:** The namespace catalog is itself a linearizable namespace called `_catalog`. It uses the exact same Raft machinery as every other linearizable namespace.

### What lives in `_catalog`

- Namespace name → {consistency_level, replication_factor, version, created_at}
- Shard map: shard_id → owning node set (per namespace)
- Shard split records

### What does NOT live in `_catalog`

- Per-namespace Raft group internal state (each group manages its own)
- The hash ring (computed locally from SWIM)
- Data

### Bootstrap Sequence

1. First node starts. Creates `_catalog` as a single-node Raft group.
2. Additional nodes join via SWIM. The `_catalog` Raft leader adds them via standard membership change.
3. `_catalog` stabilizes at a small fixed replication factor (3 or 5 nodes). Never auto-rebalances.
4. All namespace create/delete/reconfig operations are writes to `_catalog`, serialized through Raft.
5. Gossip disseminates the catalog for read optimization — nodes cache it locally. But the Raft group is the source of truth.

### Degradation

If the `_catalog` Raft group is unavailable: locally cached configs continue to serve the data plane. Namespace creation/modification/deletion is blocked until `_catalog` recovers. The data plane is unaffected.

## Sharding

### Fixed Virtual Shards

Each namespace is divided into a fixed number of virtual shards (default 16,384). Keys hash to a shard. Shards are the unit of placement, migration, and ownership.

- No split/merge in the common case
- Shard map (shard → owner set) lives in `_catalog`
- Fine-grained enough for balanced placement across hundreds of nodes
- Shard assignment follows the consistent hash ring

### Hot Shard Split (Escape Hatch)

When a shard exceeds a throughput threshold under sustained pressure:

1. The owning node detects the hot shard (request rate, queue depth)
2. Owner proposes a split to `_catalog`: shard N → shard N-a and N-b, split at median key
3. `_catalog` commits the split. Shard map grows by one entry.
4. Owner partitions data locally. Half can migrate if needed.
5. Clients with cached routing get a redirect on next request.

No merge operation. Cold split shards stay split — two cold shards cost nearly nothing. The shard count might grow from 16,384 to 16,500 over the cluster's lifetime.

### Hot Key Mitigation

If a single key dominates traffic rather than a range:

- **Read-heavy hot key:** Fan out read replicas for that shard
- **Write-heavy hot key:** This is an application-level problem. Surface metrics so users can redesign their key schema. No storage engine can make a single mutex fast.

## Data Migration

### Read Copy Migration

When a key/shard is repeatedly read from a remote region, a read replica migrates to that region based on access pattern detection.

- Authoritative copy stays in place
- Read replicas serve from local state
- For eventually consistent namespaces: reads may be slightly stale (bounded by replication lag)
- For linearizable namespaces: stale reads available if client opts in, strong reads forwarded to leader

### Write Ownership Migration (Shard Migration)

When a shard receives sustained writes from a remote region, the entire shard can migrate:

- For linearizable namespaces: Raft leader preference shifts to the region with the most writes. The Raft group membership may not change, but the leader being local saves a cross-region hop per write.
- Shard migration is committed through `_catalog`
- Old replicas transition to followers or drop the shard
- In-flight requests during migration get redirected

## Client Routing

### Any-Node Ingress with DSR

Clients connect to any node. If the node is not the shard owner:

1. Node forwards the request to the owner via QUIC (null-cipher intra-cluster)
2. Owner processes the request
3. Owner responds **directly to the client** (Direct Server Return), skipping the forwarding node on the return path
4. Response includes a routing hint: "for this shard, talk to node X next time"
5. Client caches the hint. Subsequent requests go directly to the owner.

The forwarding hop only costs latency on the request path, and only until the client learns the topology organically through usage. No need to ship the full membership or hash ring to clients.

## Client Protocol

### Binary Protocol (QUIC)

Primary path for production traffic. One QUIC stream per request, multiplexed over a single connection.

Wire format (minimal, fixed-cost parsing):
```
[request_type: u8]
[flags: u8]
[namespace_len: u16] [namespace: bytes]
[key_len: u32] [key: bytes]
[value_len: u64] [value: bytes]  // omitted for reads
```

Request types: GET, PUT, DELETE, LIST (range scan), WATCH (future)

Response includes:
- Status code
- Value (for reads)
- Routing hint (shard → node mapping for client-side caching)

### HTTP REST API

Secondary path for debugging, admin, and low-friction onboarding.

```
GET    /v1/{namespace}/{key}
PUT    /v1/{namespace}/{key}
DELETE /v1/{namespace}/{key}
GET    /v1/{namespace}?prefix=...&limit=...
```

Currently HTTP/1.1. The interface is version-agnostic — HTTP/2 (TCP) and HTTP/3 (QUIC) are future codec additions, not redesigns.

Same backend as binary protocol. The HTTP layer is a thin translation.

## Storage Engine

### WiscKey-Style Hybrid: LSM + Value Log

Key-value separation based on a size threshold. Small values are stored inline in the LSM. Large values are stored in a separate append-only value log with a pointer from the LSM.

```
Write Path:
                                    ┌──────────────┐
  key + value ──→ WAL (append) ──→  │   Memtable   │
                                    │  (in-memory)  │
                                    └──────┬───────┘
                                           │ flush
                              ┌────────────┴────────────┐
                              │                         │
                     value <= threshold          value > threshold
                              │                         │
                      ┌───────▼────────┐       ┌────────▼───────┐
                      │  LSM SSTable   │       │   Value Log    │
                      │ (key+value     │       │ (append-only,  │
                      │  inline)       │       │  large blobs)  │
                      └────────────────┘       └────────────────┘
                              │
                        compaction
                      (small data only,
                       fast, low I/O)
```

**Why this split matters:**
- Compaction only touches the LSM, which contains keys + small values + pointers. It never rewrites multi-MB blobs.
- Write amplification drops dramatically for large-value workloads (CDN, blob storage).
- The LSM stays small and cache-friendly.
- The value log is simple: append writes, offset-based reads, background GC for dead entries.

### WAL (Write-Ahead Log)

Every write appends to the WAL before any other action. The WAL is the replication unit — Raft ships WAL entries for linearizable namespaces, async replication ships them for eventually consistent ones.

- Sequential writes via direct I/O (`O_DIRECT | O_DSYNC`)
- Aligned write buffers (4KB minimum, tunable)
- Batching: group multiple writes into a single WAL entry when possible
- WAL segments rotate at a configurable size (e.g., 64MB)

### Memtable

In-memory sorted structure that absorbs writes before flushing to disk.

- Concurrent reads during writes (immutable memtable swap on flush)
- Configurable size threshold triggers flush
- Specific data structure (skip list, B-tree, ART) to be determined during implementation based on benchmarking

### LSM Sorted Files

Flushed memtables become immutable sorted files (SSTables). Organized in levels with size-tiered or leveled compaction.

- Bloom filters for negative lookups (avoid unnecessary I/O)
- Block-based format with per-block compression (optional)
- Index blocks cached in userspace block cache (not page cache)
- Direct I/O for all reads — we manage our own cache, no page cache pollution from compaction

### Value Log

Append-only log for values exceeding the separation threshold.

- Sequential append writes (direct I/O)
- Reads by offset: one I/O per value fetch
- Background garbage collection: scan for dead entries (overwritten/deleted keys), rewrite live entries to a new segment, update LSM pointers
- GC is rate-limited to avoid interfering with foreground I/O

### I/O Engine: io_uring + Direct I/O

All disk I/O goes through io_uring with direct I/O, following the same philosophy as XDP for networking: bypass the kernel, own the I/O path, poll for completions.

- Submission queue (SQ) is memory-mapped — submitting I/O ops requires no syscall
- Completion queue (CQ) polled in the busy-loop runtime alongside XDP completion rings
- Single event loop handles both network and disk I/O without blocking
- Aligned buffers for direct I/O compliance
- Future: SPDK for full kernel-bypass NVMe access (drop-in acceleration, same submit/poll interface)

### Integration with Runtime

The busy-loop local runtime gains an additional poll step:

```
Loop:
  1. [Network RX]   XDP socket recv
  2. [Dispatch]      Protocol handlers
  3. [Poll Futures]  User tasks + storage engine async ops
  4. [Timers]        Timer wheel
  5. [Disk I/O]      io_uring completion queue poll    ← NEW
  6. [Network TX]    XDP socket send
  7. [Recycle]       Frame accounting
```

Storage engine operations (WAL write, memtable flush, SST read, compaction) are submitted as io_uring ops and completed asynchronously within the same busy-loop.

## Data Path: End to End

### Write (Linearizable Namespace)

1. Client sends `PUT namespace=orders key=abc value=...` to any node
2. Node hashes key → shard ID, looks up shard map (locally cached from `_catalog`) → Raft leader
3. If not the leader: forward via QUIC, DSR response back to client with routing hint
4. Leader appends to WAL (direct I/O, io_uring)
5. Leader replicates WAL entry to Raft followers
6. Quorum of followers acknowledge
7. Leader applies to memtable, responds to client
8. Background: memtable flushes to SST + value log, compaction runs

### Write (Eventually Consistent Namespace)

1. Same routing as above, but any replica accepts the write
2. Node appends to WAL, applies to memtable, responds to client immediately
3. Async replication ships WAL entries to other replicas
4. Conflict resolution: last-writer-wins

### Read (Linearizable, Strong)

1. Route to Raft leader
2. Leader confirms leadership (lease-based)
3. Check memtable → LSM levels (bloom filter → index → data block) → value log if separated
4. Respond to client

### Read (Linearizable, Stale OK)

1. Route to any replica (including read copies)
2. Read from local state
3. Bounded staleness based on replication lag

### Read (Eventually Consistent)

1. Route to any replica
2. Read from local state
3. Respond

## Future Extensions

- **HTTP/2 and HTTP/3**: codec-layer additions to the HTTP interface
- **SPDK**: kernel-bypass NVMe access replacing io_uring for the storage engine
- **Vector clocks**: richer conflict resolution for eventually consistent namespaces
- **WATCH/subscribe**: key change notifications over QUIC streams
- **Range partitioning**: alternative to hash partitioning for ordered key workloads
- **CDN layer**: built on read copy migration + eventually consistent namespaces
- **Execution fabric**: serverless functions triggered by key mutations
- **Global queue**: built on linearizable namespaces with ordered key ranges
