//! End-to-end group behaviour between several in-process members.

use mls::crypto::CipherSuite;
use mls::group::*;
use mls::messages::*;
use mls::Codec;
use proptest::prelude::*;

const CS: CipherSuite = CipherSuite(1);

struct World {
    members: Vec<Option<Group>>,
}

impl World {
    fn new(cs: CipherSuite, config: GroupConfig) -> World {
        let g = Group::create(cs, Signer::generate(cs, b"m0"), b"group".to_vec(), vec![], config).unwrap();
        World { members: vec![Some(g)] }
    }

    fn active(&self) -> Vec<usize> {
        self.members.iter().enumerate().filter(|(_, g)| g.as_ref().map(|g| g.is_active()).unwrap_or(false)).map(|(i, _)| i).collect()
    }

    /// Deliver `msg` to every active member except `from`.
    fn broadcast(&mut self, from: usize, msg: &MlsMessage) {
        let wire = msg.to_bytes();
        for i in self.active() {
            if i == from {
                continue;
            }
            let m = MlsMessage::from_bytes(&wire).unwrap();
            self.members[i].as_mut().unwrap().process(&m).unwrap();
        }
    }

    fn commit(&mut self, by: usize, extra: Vec<Proposal>, joiners: Vec<KeyPackageBundle>) {
        let out = self.members[by].as_mut().unwrap().commit(extra, CommitOptions::default()).unwrap();
        self.broadcast(by, &out.commit);
        self.members[by].as_mut().unwrap().merge_pending_commit().unwrap();
        if let Some(MlsMessage::Welcome(w)) = &out.welcome {
            let w = Welcome::from_bytes(&w.to_bytes()).unwrap();
            for kpb in joiners {
                let config = self.members[by].as_ref().unwrap().config.clone();
                let g = Group::join(&w, &kpb, None, PskStore::default(), config).unwrap();
                self.members.push(Some(g));
            }
        }
    }

    fn add(&mut self, by: usize, n: usize) {
        let cs = self.members[by].as_ref().unwrap().cs;
        let mut props = vec![];
        let mut kpbs = vec![];
        for _ in 0..n {
            let id = format!("m{}", self.members.len() + kpbs.len());
            let kpb = create_key_package(cs, &Signer::generate(cs, id.as_bytes())).unwrap();
            props.push(Proposal::Add(kpb.key_package.clone()));
            kpbs.push(kpb);
        }
        self.commit(by, props, kpbs);
    }

    fn leaf_of(&self, i: usize) -> u32 {
        self.members[i].as_ref().unwrap().own_leaf()
    }

    fn assert_agree(&self) {
        let act = self.active();
        let a = self.members[act[0]].as_ref().unwrap();
        for i in &act[1..] {
            let b = self.members[*i].as_ref().unwrap();
            assert_eq!(a.epoch(), b.epoch());
            assert_eq!(a.epoch_authenticator(), b.epoch_authenticator(), "member {i} diverged");
            assert_eq!(a.tree().root_tree_hash(), b.tree().root_tree_hash());
        }
    }

    fn chat(&mut self) {
        for s in self.active() {
            let text = format!("hello from {s}");
            let m = self.members[s].as_mut().unwrap().encrypt_application(text.as_bytes(), b"").unwrap();
            let wire = m.to_bytes();
            for r in self.active() {
                if r == s {
                    continue;
                }
                let got = self.members[r].as_mut().unwrap().process(&MlsMessage::from_bytes(&wire).unwrap()).unwrap();
                match got {
                    Processed::Application { data, .. } => assert_eq!(data, text.as_bytes()),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }
}

#[test]
fn add_chat_remove_update_all_suites() {
    for s in mls::crypto::SUPPORTED_SUITES {
        let mut w = World::new(CipherSuite(s), GroupConfig::default());
        w.add(0, 3);
        w.assert_agree();
        w.chat();
        // Member 2 removes member 1.
        let l1 = w.leaf_of(1);
        w.commit(2, vec![Proposal::Remove(l1)], vec![]);
        assert!(!w.members[1].as_ref().unwrap().is_active());
        w.assert_agree();
        w.chat();
        // Member 3 proposes an update, member 0 commits it.
        let (p, _) = w.members[3].as_mut().unwrap().propose_update().unwrap();
        w.broadcast(3, &p);
        w.commit(0, vec![], vec![]);
        w.assert_agree();
        w.chat();
    }
}

#[test]
fn encrypted_handshake_and_padding() {
    let cfg = GroupConfig { encrypt_handshake: true, padding: 32, ..Default::default() };
    let mut w = World::new(CS, cfg);
    w.add(0, 4);
    let l4 = w.leaf_of(4);
    let (p, _) = w.members[2].as_mut().unwrap().propose_remove(l4).unwrap();
    assert!(matches!(p, MlsMessage::Private(_)));
    w.broadcast(2, &p);
    w.commit(1, vec![], vec![]);
    w.assert_agree();
    w.chat();
}

#[test]
fn concurrent_commits_one_wins() {
    let mut w = World::new(CS, GroupConfig::default());
    w.add(0, 3);
    let a = w.members[1].as_mut().unwrap().commit(vec![], CommitOptions { force_path: true, ..Default::default() }).unwrap();
    let b = w.members[2].as_mut().unwrap().commit(vec![], CommitOptions { force_path: true, ..Default::default() }).unwrap();
    // The server orders a first: everyone applies a; member 2 drops its own staged commit.
    for i in [0, 3] {
        w.members[i].as_mut().unwrap().process(&a.commit).unwrap();
    }
    w.members[1].as_mut().unwrap().process(&a.commit).unwrap(); // own commit echoed back
    let g2 = w.members[2].as_mut().unwrap();
    g2.clear_pending_commit();
    g2.process(&a.commit).unwrap();
    w.assert_agree();
    // b is now stale and rejected by everyone.
    let err = w.members[0].as_mut().unwrap().process(&b.commit).unwrap_err();
    assert!(matches!(err, mls::Error::WrongEpoch { .. }));
}

#[test]
fn applying_both_concurrent_commits_forks() {
    // Without ordering, members that apply different commits end up in different groups.
    let mut w = World::new(CS, GroupConfig::default());
    w.add(0, 3);
    let a = w.members[1].as_mut().unwrap().commit(vec![], CommitOptions { force_path: true, ..Default::default() }).unwrap();
    let b = w.members[2].as_mut().unwrap().commit(vec![], CommitOptions { force_path: true, ..Default::default() }).unwrap();
    w.members[0].as_mut().unwrap().process(&a.commit).unwrap();
    w.members[3].as_mut().unwrap().process(&b.commit).unwrap();
    let e0 = w.members[0].as_ref().unwrap().epoch_authenticator().to_vec();
    let e3 = w.members[3].as_ref().unwrap().epoch_authenticator().to_vec();
    assert_eq!(w.members[0].as_ref().unwrap().epoch(), w.members[3].as_ref().unwrap().epoch());
    assert_ne!(e0, e3);
}

#[test]
fn late_application_message_from_previous_epoch() {
    let mut w = World::new(CS, GroupConfig::default());
    w.add(0, 2);
    let late = w.members[1].as_mut().unwrap().encrypt_application(b"sent before the commit", b"").unwrap();
    w.commit(0, vec![], vec![]);
    match w.members[2].as_mut().unwrap().process(&late).unwrap() {
        Processed::Application { data, epoch, .. } => {
            assert_eq!(data, b"sent before the commit");
            assert_eq!(epoch, 1);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn external_join() {
    let cfg = GroupConfig { external_pub_extension: true, ..Default::default() };
    let mut w = World::new(CS, cfg.clone());
    w.add(0, 2);
    let gi = w.members[1].as_ref().unwrap().group_info(true, true).unwrap();
    let gi = GroupInfo::from_bytes(&gi.to_bytes()).unwrap();
    let (g, commit) = Group::join_external(&gi, None, Signer::generate(CS, b"outsider"), None, PskStore::default(), cfg).unwrap();
    w.broadcast(usize::MAX, &commit);
    w.members.push(Some(g));
    w.assert_agree();
    w.chat();
}

#[test]
fn external_psk_in_commit_and_welcome() {
    let mut w = World::new(CS, GroupConfig::default());
    w.add(0, 1);
    for g in w.members.iter_mut().flatten() {
        g.psks.external.insert(b"psk-id".to_vec(), b"shared secret".to_vec());
    }
    let id = PreSharedKeyId { psk: Psk::External { psk_id: b"psk-id".to_vec() }, psk_nonce: vec![7; 32] };
    w.commit(1, vec![Proposal::PreSharedKey(id)], vec![]);
    w.assert_agree();
}

#[test]
fn removed_member_cannot_read_new_epoch() {
    let mut w = World::new(CS, GroupConfig::default());
    w.add(0, 2);
    let l2 = w.leaf_of(2);
    let mut removed_copy = w.members[2].clone().unwrap();
    w.commit(0, vec![Proposal::Remove(l2)], vec![]);
    let m = w.members[1].as_mut().unwrap().encrypt_application(b"secret", b"").unwrap();
    assert!(removed_copy.process(&m).is_err());
}

#[derive(Debug, Clone)]
enum Op {
    Add(usize),
    Remove(usize, usize),
    Update(usize, usize),
    Chat,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..8).prop_map(Op::Add),
        (0usize..8, 0usize..8).prop_map(|(a, b)| Op::Remove(a, b)),
        (0usize..8, 0usize..8).prop_map(|(a, b)| Op::Update(a, b)),
        Just(Op::Chat),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, .. ProptestConfig::default() })]

    /// Random adds, removes and updates keep every member in agreement.
    #[test]
    fn random_operations_keep_members_in_sync(ops in proptest::collection::vec(op(), 1..14)) {
        let mut w = World::new(CS, GroupConfig::default());
        w.add(0, 1);
        for o in ops {
            let act = w.active();
            match o {
                Op::Add(by) => w.add(act[by % act.len()], 1),
                Op::Remove(by, who) => {
                    if act.len() < 3 { continue; }
                    let by = act[by % act.len()];
                    let who = act[who % act.len()];
                    if by == who { continue; }
                    let l = w.leaf_of(who);
                    w.commit(by, vec![Proposal::Remove(l)], vec![]);
                }
                Op::Update(who, by) => {
                    let who = act[who % act.len()];
                    let by = act[by % act.len()];
                    if who == by { continue; }
                    let (p, _) = w.members[who].as_mut().unwrap().propose_update().unwrap();
                    w.broadcast(who, &p);
                    w.commit(by, vec![], vec![]);
                }
                Op::Chat => w.chat(),
            }
            w.assert_agree();
        }
    }
}
