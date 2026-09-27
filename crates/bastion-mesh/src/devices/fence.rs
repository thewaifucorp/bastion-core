//! The epoch a device acts in, and whether it has been superseded.
//!
//! Shared by a primary's [`super::hub::PrimaryHub`] and its
//! [`super::log::EventLog`]: the moment the primary learns a newer epoch
//! exists — a node that saw it, or an explicit step-down — the fence closes,
//! the log refuses every further write and the hub stops giving orders. Two
//! primaries can therefore never both write in one epoch (BMD-21), and only
//! the primary of the current epoch refreshes credentials (BMD-32).

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct EpochFence {
    epoch: AtomicU64,
    /// Newest epoch known to exist above ours; 0 when none.
    superseded_by: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this device was primary of epoch {epoch}; epoch {newer} exists, so it no longer accepts writes")]
pub struct Superseded {
    pub epoch: u64,
    pub newer: u64,
}

impl EpochFence {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch: AtomicU64::new(epoch),
            superseded_by: AtomicU64::new(0),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Learn that `epoch` exists. Closes the fence when it is newer than
    /// ours; returns whether it did.
    pub fn observe(&self, epoch: u64) -> bool {
        if epoch > self.epoch() {
            self.superseded_by.fetch_max(epoch, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Ok while this device is the primary of the newest epoch it knows.
    pub fn check(&self) -> Result<(), Superseded> {
        match self.superseded_by.load(Ordering::SeqCst) {
            0 => Ok(()),
            newer => Err(Superseded {
                epoch: self.epoch(),
                newer,
            }),
        }
    }

    /// Whether this device may refresh credentials (BMD-32): only the primary
    /// of the current epoch does, so a stale one never trips the provider's
    /// refresh-token reuse detection.
    pub fn may_refresh(&self) -> bool {
        self.check().is_ok()
    }

    /// Become primary of `epoch` (a promotion). Reopens the fence.
    pub fn promote_to(&self, epoch: u64) {
        self.epoch.store(epoch, Ordering::SeqCst);
        self.superseded_by.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_epoch_closes_the_fence_until_promotion() {
        let fence = EpochFence::new(2);
        assert!(fence.check().is_ok());
        assert!(!fence.observe(2));
        assert!(!fence.observe(1));
        assert!(fence.observe(4));
        assert_eq!(fence.check(), Err(Superseded { epoch: 2, newer: 4 }));
        assert!(!fence.may_refresh());
        fence.promote_to(5);
        assert!(fence.check().is_ok());
        assert_eq!(fence.epoch(), 5);
    }
}
