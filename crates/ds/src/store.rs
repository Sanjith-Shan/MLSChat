//! Durable state on RocksDB. One write batch per accepted message covers the
//! log entry, the group's epoch and membership, the idempotency record and any
//! Welcomes, so a crash can never leave half of an accept on disk.

use wire::*;
use mls::codec::{Codec, Reader};
use rocksdb::{ColumnFamilyDescriptor, Direction, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use std::path::Path;

const CF_LOG: &str = "log";
const CF_META: &str = "meta";
const CF_DEDUPE: &str = "dedupe";
const CF_CURSOR: &str = "cursor";
const CF_INBOX: &str = "inbox";
const CF_KP: &str = "keypackage";

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GroupMeta {
    /// Epoch the next commit must be built on.
    pub epoch: u64,
    /// Sequence number of the next log entry.
    pub next_seq: u64,
    pub members: Vec<ClientId>,
    /// Last accepted sender_seq per sender.
    pub sender_seqs: Vec<SenderSeq>,
}
mls::impl_codec!(GroupMeta { epoch, next_seq, members, sender_seqs });

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SenderSeq {
    pub sender: ClientId,
    pub last: u64,
}
mls::impl_codec!(SenderSeq { sender, last });

impl GroupMeta {
    pub fn last_sender_seq(&self, s: &[u8]) -> u64 {
        self.sender_seqs.iter().find(|x| x.sender == s).map(|x| x.last).unwrap_or(0)
    }
    pub fn set_sender_seq(&mut self, s: &[u8], v: u64) {
        match self.sender_seqs.iter_mut().find(|x| x.sender == s) {
            Some(x) => x.last = v,
            None => self.sender_seqs.push(SenderSeq { sender: s.to_vec(), last: v }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxEntry {
    pub group_id: GroupId,
    pub start_seq: u64,
    pub welcome: Vec<u8>,
}
mls::impl_codec!(InboxEntry { group_id, start_seq, welcome });

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DedupeRecord {
    pub seq: u64,
    pub epoch: u64,
}

pub struct Store {
    db: DB,
    sync: bool,
}

fn lp(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b.len() + 4);
    b.to_vec().encode(&mut v);
    v
}

fn log_key(g: &[u8], seq: u64) -> Vec<u8> {
    let mut k = lp(g);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn pair_key(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut k = lp(a);
    k.extend_from_slice(&lp(b));
    k
}

/// Everything one accepted message writes.
pub struct Accept<'a> {
    pub delivery: &'a Delivery,
    pub meta: &'a GroupMeta,
    pub dedupe: bool,
    /// (joiner, inbox entry)
    pub welcomes: Vec<(ClientId, InboxEntry)>,
}

impl Store {
    pub fn open(path: &Path, sync: bool) -> anyhow::Result<Store> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = [CF_LOG, CF_META, CF_DEDUPE, CF_CURSOR, CF_INBOX, CF_KP].into_iter().map(|n| ColumnFamilyDescriptor::new(n, Options::default()));
        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Store { db, sync })
    }

    fn wopts(&self) -> WriteOptions {
        let mut w = WriteOptions::default();
        w.set_sync(self.sync);
        w
    }

    fn cf(&self, n: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(n).expect("column family")
    }

    pub fn group_meta(&self, g: &[u8]) -> anyhow::Result<Option<GroupMeta>> {
        Ok(match self.db.get_cf(self.cf(CF_META), g)? {
            Some(b) => Some(GroupMeta::from_bytes(&b)?),
            None => None,
        })
    }

    pub fn create_group(&self, g: &[u8], meta: &GroupMeta) -> anyhow::Result<()> {
        self.db.put_cf_opt(self.cf(CF_META), g, meta.to_bytes(), &self.wopts())?;
        Ok(())
    }

    pub fn dedupe(&self, g: &[u8], msg_id: &[u8]) -> anyhow::Result<Option<DedupeRecord>> {
        Ok(self.db.get_cf(self.cf(CF_DEDUPE), pair_key(g, msg_id))?.map(|b| DedupeRecord {
            seq: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            epoch: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        }))
    }

    /// Atomically append one accepted message.
    pub fn accept(&self, a: Accept) -> anyhow::Result<()> {
        let d = a.delivery;
        let mut b = WriteBatch::default();
        b.put_cf(self.cf(CF_LOG), log_key(&d.group_id, d.seq), d.to_bytes());
        b.put_cf(self.cf(CF_META), &d.group_id, a.meta.to_bytes());
        if a.dedupe {
            let mut v = d.seq.to_be_bytes().to_vec();
            v.extend_from_slice(&d.epoch.to_be_bytes());
            b.put_cf(self.cf(CF_DEDUPE), pair_key(&d.group_id, &d.msg_id), v);
        }
        for (who, entry) in &a.welcomes {
            let next = self.inbox_next(who)?;
            b.put_cf(self.cf(CF_INBOX), log_key(who, next), entry.to_bytes());
        }
        self.db.write_opt(b, &self.wopts())?;
        Ok(())
    }

    /// Log entries of a group from `from_seq` on.
    pub fn read_log(&self, g: &[u8], from_seq: u64) -> anyhow::Result<Vec<Delivery>> {
        let prefix = lp(g);
        let start = log_key(g, from_seq);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_LOG), IteratorMode::From(&start, Direction::Forward)) {
            let (k, v) = item?;
            if !k.starts_with(&prefix) || k.len() != prefix.len() + 8 {
                break;
            }
            out.push(Delivery::from_bytes(&v)?);
        }
        Ok(out)
    }

    /// Cursors are advisory (a lost one only causes a re-fetch), so they are not fsynced.
    pub fn set_cursor(&self, client: &[u8], g: &[u8], seq: u64) -> anyhow::Result<()> {
        self.db.put_cf(self.cf(CF_CURSOR), pair_key(client, g), seq.to_be_bytes())?;
        Ok(())
    }

    pub fn cursors(&self, client: &[u8]) -> anyhow::Result<Vec<(GroupId, u64)>> {
        let prefix = lp(client);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_CURSOR), IteratorMode::From(&prefix, Direction::Forward)) {
            let (k, v) = item?;
            if !k.starts_with(&prefix) {
                break;
            }
            let mut r = Reader::new(&k[prefix.len()..]);
            let g = Vec::<u8>::decode(&mut r)?;
            out.push((g, u64::from_be_bytes(v[..8].try_into()?)));
        }
        Ok(out)
    }

    pub fn inbox_next(&self, client: &[u8]) -> anyhow::Result<u64> {
        let prefix = lp(client);
        let mut it = self.db.iterator_cf(self.cf(CF_INBOX), IteratorMode::From(&log_key(client, u64::MAX), Direction::Reverse));
        if let Some(item) = it.next() {
            let (k, _) = item?;
            if k.starts_with(&prefix) && k.len() == prefix.len() + 8 {
                return Ok(u64::from_be_bytes(k[prefix.len()..].try_into()?) + 1);
            }
        }
        Ok(0)
    }

    pub fn read_inbox(&self, client: &[u8], from: u64) -> anyhow::Result<Vec<(u64, InboxEntry)>> {
        let prefix = lp(client);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_INBOX), IteratorMode::From(&log_key(client, from), Direction::Forward)) {
            let (k, v) = item?;
            if !k.starts_with(&prefix) || k.len() != prefix.len() + 8 {
                break;
            }
            out.push((u64::from_be_bytes(k[prefix.len()..].try_into()?), InboxEntry::from_bytes(&v)?));
        }
        Ok(out)
    }

    pub fn put_key_package(&self, client: &[u8], kp: &[u8]) -> anyhow::Result<()> {
        let h = mls::CipherSuite(1).hash(kp);
        self.db.put_cf_opt(self.cf(CF_KP), pair_key(client, &h), kp, &self.wopts())?;
        Ok(())
    }

    /// Take (and delete) one key package published by `client`.
    pub fn take_key_package(&self, client: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let prefix = lp(client);
        let found = {
            let mut it = self.db.iterator_cf(self.cf(CF_KP), IteratorMode::From(&prefix, Direction::Forward));
            match it.next() {
                Some(item) => {
                    let (k, v) = item?;
                    if k.starts_with(&prefix) {
                        Some((k.to_vec(), v.to_vec()))
                    } else {
                        None
                    }
                }
                None => None,
            }
        };
        if let Some((k, v)) = found {
            self.db.delete_cf_opt(self.cf(CF_KP), k, &self.wopts())?;
            return Ok(Some(v));
        }
        Ok(None)
    }
}
