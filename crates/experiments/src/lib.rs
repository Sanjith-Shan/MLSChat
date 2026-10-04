//! Shared setup for the experiments.

use mls::group::{create_key_package, CommitOptions, Group, GroupConfig, KeyPackageBundle, PskStore, Signer};
use mls::messages::{MlsMessage, Proposal};
use mls::CipherSuite;
use std::time::Instant;

/// A group of `n` members whose ratchet tree is fully populated, as it is in a
/// group where everyone has committed at least once (the steady state), plus
/// real joined states for the members the experiment measures.
pub struct BigGroup {
    pub cs: CipherSuite,
    pub n: usize,
    /// Real state of leaf 0 (the creator).
    pub creator: Group,
    /// Real states of the measured members, joined by Welcome.
    pub measured: Vec<Group>,
    /// Key material of every member (index = leaf index; entry 0 unused).
    pub kpbs: Vec<Option<KeyPackageBundle>>,
    pub build_seconds: f64,
    pub fill_commits: usize,
}

fn bit_reverse(mut x: u32, bits: u32) -> u32 {
    let mut r = 0;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

pub fn config() -> GroupConfig {
    GroupConfig { max_past_epochs: 0, ..Default::default() }
}

/// Build the group with real protocol messages:
/// 1. the creator adds everyone in one commit (one Welcome);
/// 2. one member under every lowest-level parent commits an empty commit with a
///    path, in bit-reversed order, so every parent node ends up holding a key.
///
/// Commits from unmeasured members are produced from the shared group state
/// with that member's own keys (`Group::impersonate`), and the measured members
/// process every one of them, so their state is exactly a real member's state.
pub fn build(cs: CipherSuite, n: usize, measured_leaves: &[u32]) -> BigGroup {
    let t0 = Instant::now();
    let mut creator = Group::create(cs, Signer::generate(cs, b"member-0"), b"big-group".to_vec(), vec![], config()).unwrap();
    let mut kpbs: Vec<Option<KeyPackageBundle>> = vec![None];
    let mut adds = Vec::with_capacity(n);
    for i in 1..n {
        let kpb = create_key_package(cs, &Signer::generate(cs, format!("member-{i}").as_bytes())).unwrap();
        adds.push(Proposal::Add(kpb.key_package.clone()));
        kpbs.push(Some(kpb));
    }
    let mut measured = Vec::new();
    if n > 1 {
        let out = creator.commit(adds, CommitOptions { force_path: true, ..Default::default() }).unwrap();
        creator.merge_pending_commit().unwrap();
        let Some(MlsMessage::Welcome(w)) = out.welcome else { panic!("no welcome") };
        for l in measured_leaves {
            let kpb = kpbs[*l as usize].as_ref().unwrap();
            measured.push(Group::join(&w, kpb, None, PskStore::default(), config()).unwrap());
        }
    }
    // Fill: leaves 2i+1 (never a measured even leaf), in bit-reversed order of i.
    let pairs = (n / 2) as u32;
    let bits = 32 - pairs.next_power_of_two().leading_zeros() - 1;
    let mut order: Vec<u32> = (0..pairs.next_power_of_two()).map(|i| bit_reverse(i, bits)).filter(|i| *i < pairs).collect();
    order.dedup();
    let mut fill_commits = 0;
    for i in order {
        let leaf = 2 * i + 1;
        if measured_leaves.contains(&leaf) || leaf as usize >= n {
            continue;
        }
        let kpb = kpbs[leaf as usize].clone().unwrap();
        let mut sim = creator.impersonate(leaf, kpb.signer.clone(), kpb.encryption_priv.clone());
        let out = sim.commit(vec![], CommitOptions { force_path: true, ..Default::default() }).unwrap();
        // The member's new leaf key comes from its own commit.
        sim.merge_pending_commit().unwrap();
        let new_priv = sim.private_state().keys[&(2 * leaf)].clone();
        kpbs[leaf as usize].as_mut().unwrap().encryption_priv = new_priv;
        creator.process(&out.commit).unwrap();
        for m in measured.iter_mut() {
            m.process(&out.commit).unwrap();
        }
        fill_commits += 1;
    }
    BigGroup { cs, n, creator, measured, kpbs, build_seconds: t0.elapsed().as_secs_f64(), fill_commits }
}

impl BigGroup {
    /// Parent nodes holding a key, out of parents with members under both children.
    pub fn parent_fill(&self) -> (usize, usize) {
        let t = self.creator.tree();
        let mut filled = 0;
        let mut total = 0;
        for x in (1..(2 * t.n_leaves() - 1)).step_by(2) {
            // A parent whose left or right subtree has no members is never on a filtered
            // direct path, so RFC 9420 leaves it blank. Count only parents that can hold a key.
            let under = |c: u32| mls::tree_math::leaves_under(c).any(|l| t.leaf(l).is_some());
            let has_member = under(mls::tree_math::left(x).unwrap()) && under(mls::tree_math::right(x).unwrap());
            if has_member {
                total += 1;
                if !t.is_blank(x) {
                    filled += 1;
                }
            }
        }
        (filled, total)
    }
}

pub fn median(v: &mut [f64]) -> f64 {
    harness::median(v)
}

/// Group sizes used by exp1 and exp2.
pub const SIZES: [usize; 8] = [2, 10, 50, 100, 500, 1000, 5000, 10000];
