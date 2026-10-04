# MLSChat design

This document explains how MLSChat is built and why. Measured numbers live in `NUMBERS.md`, each
with the `results/*.jsonl` file it came from.

## Architecture

```
  browser (WASM)        native client          native client
  crates/web            crates/client          crates/client
      |  MLS library (crates/mls) runs on every device; keys never leave it
      |                     |                      |
      +-------- WebSocket, binary frames (crates/wire) ---------+
                            |
                 delivery service (crates/ds)
                 Tokio, one task per connection
                 per-group mutex: fence, append, fan out
                            |
                 RocksDB (bundled): log, meta, dedupe,
                 cursor, inbox, keypackage column families
```

| Crate | What it is |
| --- | --- |
| `mls` | RFC 9420 client library: codec, crypto and HPKE, tree math, ratchet tree, TreeKEM, key schedule, secret tree, framing, group state machine |
| `conformance` | Runs the 16 `mlswg/mls-implementations` vector files |
| `differential` | Randomized mixed MLSChat/OpenMLS sessions |
| `wire` | Client/server protocol, shared by server, native client and WASM client |
| `ds` | Delivery service |
| `client` | Native client: MLS state plus a resilient server connection |
| `baselines` | Pairwise and Sender Keys on the same primitives |
| `experiments` | exp1 to exp4 |
| `harness` | Machine and load metadata for every result line |
| `web` | Browser client (WASM) |

## The MLS library

Written from RFC 9420, not ported. Every structure has a hand-written TLS encoding (`codec.rs`)
with the MLS variable-length integer, which rejects non-minimal lengths.

**Crypto.** All seven RFC 9420 cipher suites. The primitives come from RustCrypto and dalek
crates (X25519, P-256/384/521, X448, Ed25519, ECDSA, Ed448, AES-GCM, ChaCha20-Poly1305,
SHA-2, HKDF, HMAC). HPKE (RFC 9180, base mode, plus export for external commits) is written here
on top of them, so every byte of MLS-facing crypto is exercised by the crypto-basics vectors.
ECDSA signatures are DER encoded, as the vectors require.

**Ratchet tree.** An array of nodes, always padded to a power of two leaves. Nodes are shared
(`Arc`) so a commit can clone the tree for its staged next epoch without copying 10,000 leaf
nodes. Tree hashes are cached per node and invalidated along the direct path of each change.
Parent-hash validation is the top-down check from RFC 9420 section 7.9.2: every non-blank parent
must be parent-hash valid with respect to exactly one descendant.

**Staged commits.** `Group::commit` never changes the group. It returns the outgoing messages and
keeps the next epoch in `pending`. The client merges it only when it meets its own commit in the
server's log (or, in the exp3 client policy, when the server acknowledges it), and drops it when
another commit wins the epoch. This is the client half of epoch fencing.

**Past epochs.** A member keeps the secret tree and the (shared-node) public tree of the last
two epochs, so an application message encrypted just before a commit still decrypts after it.

**What is left out.** Lifetime checks against the clock are skipped (no trusted time source is
assumed). X.509 credentials are parsed but not validated. Custom proposals and extensions beyond
RFC 9420's five are carried but not interpreted.

## The delivery service

MLS assumes a delivery service that gives every member the same order of commits
(RFC 9750 section 5). The server here provides four guarantees:

1. **One order per group.** Every accepted message, commit or application, gets the next
   sequence number in the group's log. A per-group async mutex covers fence check, durable
   append and fan-out, so pushes to each connection leave in sequence order.
2. **Epoch fencing.** A commit (or proposal) is accepted only if it was built on the group's
   current epoch. The server learns the epoch from the clear-text MLS framing header; it never
   decrypts anything. A loser gets `StaleEpoch` and the current epoch, catches up, and retries.
3. **Idempotent sends.** Each request carries a client-chosen 16-byte id. The id is written to a
   dedupe column family in the same RocksDB write batch as the log entry, so after a crash and a
   retry the server answers with the original sequence number instead of appending again.
4. **Catch-up by cursor.** A client applies the log strictly in sequence order. Early entries
   are buffered, already-applied ones dropped, gaps filled by `Fetch` from its position.
   Welcomes go to a per-device inbox with the log position the joiner should start from.

Writes use `sync = true` (the WAL is fsynced before the ack). One write batch per accepted
message covers the log entry, the group's epoch and membership, the dedupe record and any
Welcomes, so a crash can never leave half an accept on disk.

**Why fencing and not just ordering.** The TLA+ model (`docs/tla/`) separates the two. With an
ordered log and clients that apply strictly in log order and skip stale commits, members never
fork even without fencing. But the server then acknowledges commits that never take effect
(`AckMeansApplied` fails in 6 steps), and a client that trusts the ack (or a newcomer who got
that commit's Welcome) ends up on a branch nobody else is on. Fencing makes the acknowledgement
mean "this is the commit for epoch e", which is what lets the committer merge and the newcomer
join safely. exp3 measures the same three servers with real clients.

| Configuration | NoFork | AckMeansApplied | States |
| --- | --- | --- | --- |
| fenced, merge on ack, 3 clients | holds | holds | 8,914 |
| fenced, merge on ack, 2 clients x 2 commits | holds | holds | 50,869 |
| fenced, merge in log order | holds | holds | 5,068 |
| ordered, unfenced, merge in log order | holds | violated | 16,220 (NoFork only) |
| ordered, unfenced, merge on ack | violated | violated | |
| relay (no order) | violated | violated | |

Raw TLC output: `docs/tla/RESULTS.txt`. Retries, duplicate requests and lost replies are part
of the model, and `NoDuplicateInLog` holds in every configuration.

**Membership on the server.** The server keeps a list of device ids per group for fan-out, and
updates it from the add/remove lists that the committer attaches to an accepted commit. That list
is trusted metadata: a malicious member could lie about it and starve someone of fan-out. It
cannot add a reader, because reading needs the MLS group secrets. RFC 9750 section 5.3 discusses
the same trade-off.

## Baselines

Same primitives as suite 1 (X25519, AES-128-GCM, SHA-256, Ed25519), same codebase.

- **Pairwise.** X3DH-style session setup (three X25519 operations per side), then a symmetric hash
  ratchet per direction. The Double Ratchet's DH step per round trip is not modelled, which
  flatters pairwise on CPU.
- **Sender Keys.** Each member owns a hash-ratchet chain and an Ed25519 key, hands the chain out
  over pairwise sessions, encrypts each message once and signs it. Removing a member forces every
  remaining member to rotate and re-distribute: quadratic in total.

## Choices recorded

- **RocksDB built from the bundled source.** The mini PC's WSL has no clang and no sudo. The
  `librocksdb-sys` build needs libclang only for bindgen; it comes from the `libclang` Python
  wheel in a project venv, with a `libclang.so.18.1` symlink and GCC's builtin headers passed via
  `BINDGEN_EXTRA_CLANG_ARGS` (`scripts/env.sh`). The C++ compiles with GCC 13. No fallback store
  was needed.
- **Everything heavy outside the repo.** Target dir, toolchains, vectors, OpenMLS sources, the
  JRE and TLC live under `$MLS_WORK` (`~/mlschat-work` on WSL ext4). The repo stays small.
- **Wire format reuses the MLS codec**, so the server's request parser is the same code the
  conformance suite exercises, and it is fuzzed with it.

## Credits

- RFC 9420, The Messaging Layer Security (MLS) Protocol.
- RFC 9750, The Messaging Layer Security (MLS) Architecture.
- RFC 9180, Hybrid Public Key Encryption.
- The `mlswg/mls-implementations` test vectors and interop harness (pinned at
  `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a`).
- OpenMLS 0.9.0, used as the differential reference.
- The Sender Keys and X3DH descriptions published by the Signal project.
- TLA+ and the TLC model checker.
