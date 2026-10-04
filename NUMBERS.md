# Numbers

Every figure MLSChat claims, the file it comes from, and how it was measured. All timing ran on a
shared mini PC (Acemagic K1, AMD Ryzen 3 4300U, Windows 11) inside a 2-vCPU WSL2 Ubuntu 24.04 VM
with about 6 GB of RAM. Other projects' containers shared the box: the 1-minute load average is
recorded on every result line and was between 4 and 21 during the runs. Treat absolute times as
upper bounds for this box, not as properties of the code. Load is simulated clients on this one
machine.

Medians are over the repetitions stated in each file (`reps`). Each line also carries the git
commit it was built from; runs after a fix were made from the working tree on top of that commit
and the fix was committed right after (see `BUG_LOG.md`).

## Conformance (exp5)

| Figure | Value | Source |
| --- | --- | --- |
| Official test-vector cases passed | **785 of 785**, 0 skipped, 0 failed | `results/exp5_conformance.jsonl` (`exp5_vectors_summary`) |
| Vector files where every case passes | **16 of 16** | same |
| Cipher suites covered | **7 of 7** (1 to 7) | same |
| Vector repository commit | `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a` | same |
| Passive-client epochs replayed | 330 epochs, 1,602 proposals on the implemented suites (200 epochs and 1,542 proposals in `passive-client-random` alone) | counted from the vector files; each epoch's authenticator is compared |
| OpenMLS differential sessions that agree | **300 of 300** (100 per suite, suites 1 to 3, 40 random operations each) | `results/exp5_conformance.jsonl` (`exp5_openmls_differential`) |
| Epochs checked across those sessions | **9,816** (4,983 commits by MLSChat members, 4,833 by OpenMLS members) | same |
| Application messages decrypted across implementations | 2,184 | same |

The differential check: after every commit, every member (a random mix of MLSChat and OpenMLS
0.9.0) must hold the same epoch, epoch authenticator and exported secret, and every application
message must decrypt to the plaintext sent.

## Interop harness (extra)

The official `mls-implementations` gRPC test-runner drove MLSChat and OpenMLS (main at `4f407c4`)
together: every script, every assignment of the two implementations to the actors, every suite
both support plus suites 4 to 7 with MLSChat alone, and both handshake modes.

| Config | Runs passed | Runs mixing both implementations | Source |
| --- | --- | --- | --- |
| welcome_join | 128 / 128 | 48 / 48 | `results/interop.jsonl` |
| commit | 2,688 / 2,688 | 2,400 / 2,400 | same |
| application | 96 / 96 | 36 / 36 | same |
| external_join | 328 / 328 | 228 / 228 | same |
| external_proposals, reinit, branch, deep_random | see `results/interop.jsonl` | | same |

## Membership cost (exp1)

Group sizes 2 to 10,000. The MLS group's ratchet tree is in its steady state: every parent node
that can hold a key holds one (9,999 of 9,999 at n = 10,000), reached with 5,000 real commits.
Times are the committer's (or one member's) CPU time for one operation.

| n = 10,000 | MLS | Sender Keys | Pairwise | Source |
| --- | --- | --- | --- | --- |
| Remove one member, sender side | **4.64 ms** committer, **2,493 B** commit | **95.0 s** total device CPU (9.50 ms per member x 9,999 members), **8.80 GB** total | 0 (nothing to re-key) | `results/exp1_membership.jsonl` |
| Remove, each receiver | 4.86 ms to process the commit | 9.50 ms each to rotate and send its own key | 0 | same |
| Add one member, committer | 56.3 ms (the Welcome carries the 2.56 MB tree) | 2.69 s for the newcomer (9,999 X3DH-style handshakes) | 2.64 s newcomer | same |
| Add, bytes | 445 B commit + 2,564,351 B Welcome (337 B without the tree) | 2.40 MB | 0.64 MB | same |
| Add, joiner processing | 631 ms (verifies 10,000 leaf signatures and the tree) | | | same |

How the Sender Keys remove figure is computed: one member's rotation (new chain plus a pairwise
encryption to each of the other 9,998 remaining members) was timed, and the aggregate is that
times the 9,999 members who must each do it. A full run of all members was timed for n up to 500
and landed within 26 percent of the multiplication, on both sides (n = 50: 2.6 ms computed, 3.5 ms
measured; n = 500: 208.9 ms computed, 196.0 ms measured).

Scaling of MLS Remove (committer): 1.51 ms at 100, 2.43 ms at 1,000, 3.50 ms at 5,000, 4.64 ms at
10,000. Before bug 6 was fixed it was 20.3 ms at 5,000 and 41.1 ms at 10,000
(`results/exp1_membership_v1_eager_groupinfo.jsonl`).

Crossover: at n = 10, Sender Keys' remove costs 0.23 ms of total CPU against MLS's 0.84 ms for the
committer, so Sender Keys is cheaper for small groups. By n = 50 it has flipped (2.6 ms against
1.26 ms), and at n = 100 Sender Keys needs 8.8 ms and 854 KB against MLS's 1.5 ms and 1.3 KB. On
bytes MLS wins from n = 10 (831 B against 6.3 KB).

## Send cost (exp2)

100-byte payload, median of 200 messages.

| Scheme | Sender time | Bytes uploaded | At n = 10,000, bytes delivered in total | Source |
| --- | --- | --- | --- | --- |
| MLS | 42.4 us at every size | 239 B | 2.39 MB | `results/exp2_send.jsonl` |
| Sender Keys | 20.4 us at every size | 184 B | 1.84 MB | same |
| Pairwise | 8.24 ms at n = 10,000 (n - 1 encryptions) | 1.20 MB | 1.20 MB | same |

MLS costs about twice Sender Keys per message (an extra AEAD for the sender data and key
derivation), and both are flat in group size.

## Concurrent commits (exp3)

6 members, 50 trials per row, 2 or 4 members committing at the same moment. The same client policy
in every mode: merge your own commit once the server acknowledges it.

| Server | Empty commits, forked trials | Add commits, forked trials | Source |
| --- | --- | --- | --- |
| Fenced (MLSChat) | 0/50 (k=2), 0/50 (k=4) | 0/50, 0/50 | `results/exp3_concurrency.jsonl` |
| Ordered, unfenced | 0/50, 0/50 | 50/50, 50/50 (150 newcomers stranded) | same |
| Relay, no order | 1/50, 7/50 | 50/50, 50/50 | same |

Fenced: **0 of 200** trials forked; the 300 losing commits were rejected and retried. In the
unfenced ordered server, existing members never forked (a stale commit is skipped by everyone),
but each losing add-commit was acknowledged and its Welcome delivered, so its newcomer joined a
branch nobody else is on.

## Chaos (exp4)

The server is a separate `mlschat-ds` process, killed with SIGKILL every 0.5 to 2 s and restarted
on the same RocksDB directory; each client also drops its connection with 2 percent probability per
send; a random member commits every 40 steps. Writes are fsynced.

| Run | Messages | Deliveries | Lost | Duplicated | Reordered | Server kills | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 clients x 300 | 2,400 | 16,800 | 0 | 0 | 0 | 9 | `results/exp4_chaos.jsonl` |
| 16 clients x 1,000 | 16,000 | 240,000 | 0 | 0 | 0 | 54 | same |
| 16 clients x 1,000 | 16,000 | 240,000 | 0 | 0 | 0 | 52 | same |
| 8 clients x 300, msg-id dedupe off | 2,400 | 16,800 | 0 | 0 | 0 | 8 | same |
| **Total** | **36,800** | **513,600** | **0** | **0** | **0** | **123** | |

Every client also saw the same global order (0 order disagreements) and all ended in one epoch
state (no fork). 755 client connections were dropped in total.

Before per-sender sequence numbers (bug 8), the 16-client run delivered 16 messages out of their
sender's order (240 delivery events), and with message-id dedupe off 1,403 messages were
duplicated (`results/exp4_chaos_v1_before_sender_seq.jsonl`).

## Model check (extra)

| Configuration | NoFork | AckMeansApplied | Distinct states | Source |
| --- | --- | --- | --- | --- |
| Fenced, 3 clients | holds | holds | 8,914 | `results/model_check.jsonl` |
| Fenced, 2 clients x 2 commits | holds | holds | 50,869 | same |
| Fenced, log-order merge | holds | holds | 5,068 | same |
| Ordered, unfenced | holds | violated (6-state trace) | 16,220 (NoFork only) | same |
| Ordered, unfenced, merge on ack | violated | violated | | same |
| Relay | violated | violated | | same |

## Delivery-service load test (extra)

Clients are real MLS members over WebSocket; latency runs from the sender's send call to the
plaintext being decrypted at each recipient, so it includes MLS encrypt, the server's fence,
fsynced append and fan-out, and MLS decrypt. The load generator shares the 2-vCPU VM with the
server and with other projects' containers. First 2 s of each 20 s step excluded.

| Shape | Offered | Deliveries/s | p50 | p99 | Server CPU | Source |
| --- | --- | --- | --- | --- | --- | --- |
| 1,000 connections, 100 groups of 10 | 100 msg/s | 900 | 4.7 ms | 124 ms | 0.07 cores | `results/loadtest.jsonl` |
| same | 250 msg/s | 2,250 | 7.3 ms | 75 ms | 0.14 cores | same |
| same | 400 msg/s | 3,600 | 9.2 ms | 332 ms | 0.20 cores | same |
| same | 600 msg/s | 5,387 | 19.0 ms | 1,151 ms | 0.25 cores | same |
| 500 connections, one group of 500 | 10 msg/s | 4,990 | 40.7 ms | 223 ms | 0.08 cores | same |
| same | 15 msg/s | 7,485 | 338 ms | 2,172 ms | 0.13 cores | same |

With fsync off the 1,000-connection numbers were no better (p99 341 ms at 250 msg/s), and the
server never used more than 0.28 cores, so the tail is CPU contention on the shared VM rather
than the disk or the server's own work.

## Fuzzing (extra)

cargo-fuzz with libFuzzer and AddressSanitizer, 10 minutes per target, seeded from the vectors.

| Target | Executions | Crashes | Source |
| --- | --- | --- | --- |
| `mls_message` (decode and canonical re-encode) | 11.7 million | 0 | run log, `BUG_LOG.md` |
| `wire_frames` (server protocol) | 24.4 million | 0 | same |
| `group_process` (a member processing arbitrary messages) | 35.9 million | 0 | same |
| `ratchet_tree` (received trees) | 97,762 before the crash in bug 12 | 1, fixed | same |

## Demo

The web demo (three WASM clients, `assets/demo.gif`) is a recording, not a measurement.
