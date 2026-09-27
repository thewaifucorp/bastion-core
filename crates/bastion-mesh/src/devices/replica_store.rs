//! A node's replica: the primary's event log, encrypted at rest (BMD-16,
//! BMD-17).
//!
//! An append-only file of records, each `len (u32 BE) ‖ nonce (12) ‖
//! ChaCha20-Poly1305(key, event JSON)`. The 32-byte key comes from the host,
//! which keeps it in the system vault (DPAPI, keyring, Keychain); without it
//! the file does not open. A node never reads its replica to act — it only
//! keeps it; at promotion [`ReplicaStore::materialize`] rebuilds a `Memory`
//! from it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::log::{apply_to_memory, EventLog};
use super::node::ReplicaSink;
use super::replica::MemoryEvent;
use crate::memory::Memory;

const AAD: &[u8] = b"bastion-replica-v1";

pub struct ReplicaStore {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    last: Mutex<Option<u64>>,
}

impl std::fmt::Debug for ReplicaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicaStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ReplicaStore {
    /// Open (or create) the replica at `path` with `key`. A wrong key, or a
    /// file that was tampered with, fails here.
    pub fn open(path: impl Into<PathBuf>, key: Zeroizing<[u8; 32]>) -> anyhow::Result<Self> {
        let path = path.into();
        let store = Self {
            cipher: ChaCha20Poly1305::new((&*key).into()),
            path,
            last: Mutex::new(None),
        };
        let last = store.read_all()?.last().map(|e| e.seq);
        *store.last.try_lock().expect("fresh mutex") = last;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every event, decrypted, in order.
    pub fn read_all(&self) -> anyhow::Result<Vec<MemoryEvent>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut events = Vec::new();
        let mut reader = &bytes[..];
        while !reader.is_empty() {
            let mut len = [0u8; 4];
            reader.read_exact(&mut len)?;
            let len = u32::from_be_bytes(len) as usize;
            if len < 12 || reader.len() < len {
                anyhow::bail!("replica file is truncated");
            }
            let (record, rest) = reader.split_at(len);
            reader = rest;
            let (nonce, ciphertext) = record.split_at(12);
            let plaintext = Zeroizing::new(
                self.cipher
                    .decrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad: AAD,
                        },
                    )
                    .map_err(|_| {
                        anyhow::anyhow!("replica does not decrypt: wrong key or tampered")
                    })?,
            );
            events.push(serde_json::from_slice(&plaintext)?);
        }
        Ok(events)
    }

    fn append(&self, events: &[MemoryEvent]) -> anyhow::Result<()> {
        let mut out = Vec::new();
        for event in events {
            let plaintext = Zeroizing::new(serde_json::to_vec(event)?);
            let mut nonce = [0u8; 12];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
            let ciphertext = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plaintext,
                        aad: AAD,
                    },
                )
                .map_err(|_| anyhow::anyhow!("replica encryption failed"))?;
            out.extend_from_slice(&((12 + ciphertext.len()) as u32).to_be_bytes());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&out)?;
        file.sync_data()?;
        Ok(())
    }

    /// Rebuild this replica into `memory` (a fresh store on the device being
    /// promoted), recording every event in `log` so the new primary's log
    /// continues the same sequence. Returns the non-belief events (sessions,
    /// personas, config) for the host to restore.
    pub async fn materialize(
        &self,
        memory: &dyn Memory,
        log: &EventLog,
    ) -> anyhow::Result<Vec<MemoryEvent>> {
        let events = self.read_all()?;
        for event in &events {
            log.import(event)?;
        }
        apply_to_memory(memory, log, &events).await
    }
}

#[async_trait]
impl ReplicaSink for ReplicaStore {
    async fn last_seq(&self) -> Option<u64> {
        *self.last.lock().await
    }

    /// Apply a batch in order: events already held are skipped, a gap is
    /// refused (the primary resends from the last acknowledged `seq`).
    async fn apply(&self, _from_seq: u64, events: Vec<MemoryEvent>) -> anyhow::Result<u64> {
        let mut last = self.last.lock().await;
        let mut fresh = Vec::new();
        let mut expected = last.map_or(1, |l| l + 1);
        for event in events {
            if last.is_some_and(|l| event.seq <= l) || event.seq < expected {
                continue;
            }
            if event.seq != expected {
                anyhow::bail!("replica gap: expected seq {expected}, got {}", event.seq);
            }
            expected += 1;
            fresh.push(event);
        }
        if !fresh.is_empty() {
            self.append(&fresh)?;
            *last = fresh.last().map(|e| e.seq);
        }
        Ok(last.unwrap_or(0))
    }
}
