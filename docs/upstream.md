# Upstream drafts

Drafts only. Nothing here has been posted; each needs a human read before it goes anywhere.

## OpenMLS: leaf node lifetime range is never checked

**Repository:** openmls/openmls. **Seen in:** 0.9.0 from crates.io and `main` at
`4f407c45857d177e7b5933d32795307b4f14b196` (2026-10-03).

**Title:** `Lifetime::has_acceptable_range` is never called, so over-long key package lifetimes are accepted

**Body:**

RFC 9420 section 10.1 says applications "MUST define a maximum total lifetime that is acceptable
for a LeafNode, and reject any LeafNode where the total lifetime is longer than this duration."
`openmls/src/key_packages/lifetime.rs` defines `MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS` (84 days
plus one hour) and `Lifetime::has_acceptable_range()`, annotated as ValSem
`openmls/annotations#32`. A search of the crate finds no caller of `has_acceptable_range`.
`KeyPackageIn::validate` calls only `life_time.validate()`, which checks that the current time is
inside `[not_before, not_after]`.

How we noticed: in a differential test, an independent RFC 9420 implementation produced key
packages with `not_before = 0` and `not_after = u64::MAX`. `KeyPackageIn::validate` accepted them
and `MlsGroup` added the members without complaint across 300 randomized sessions.

Reproduce:

```rust
// Build a KeyPackage whose leaf node lifetime is [0, u64::MAX], sign it,
// serialize it, then:
let kp = KeyPackageIn::tls_deserialize_exact(bytes)?
    .validate(provider.crypto(), ProtocolVersion::Mls10);
assert!(kp.is_err()); // fails today: validation succeeds
```

Suggested fix: call `has_acceptable_range()` in `KeyPackageIn::validate` (and wherever leaf nodes
with a `key_package` source are validated, e.g. in Add proposals received over the wire), or make
the bound configurable per group and document the default. Applications that accept the official
`mls-implementations` vectors may want the check to be opt-in, since those vectors use unbounded
lifetimes.

The same gap existed in MLSChat and is fixed there: key packages now carry an 84-day window and
groups can opt into a range bound (`GroupConfig::max_lifetime_range`).

## mls-implementations: vectors never exercise bounded lifetimes

**Repository:** mlswg/mls-implementations. Low priority, a note rather than an issue.

Every key package in the pinned vectors (`cfd4502`) we checked uses an unbounded lifetime, so no
vector tells an implementation whether it enforces the RFC 9420 section 10.1 lifetime bound. A
`passive-client-welcome` case whose joiner key package has a bounded lifetime would at least keep
implementations that enforce a bound from failing the suite.
