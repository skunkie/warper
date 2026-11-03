// SPDX-FileCopyrightText: 2026 skunkie
//
// SPDX-License-Identifier: MIT

//! Fixed-capacity open addressing with bounded tombstones and no reallocation.

use super::{Error, allocate};

const EMPTY: usize = usize::MAX;
const DELETED: usize = usize::MAX - 1;

#[derive(Clone, Copy)]
struct Bucket {
    hash: u64,
    slot: usize,
}

pub(super) struct Index {
    buckets: Vec<Bucket>,
    deleted: usize,
}

impl Index {
    pub(super) fn bucket_count(capacity: usize) -> Result<usize, Error> {
        capacity
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::InvalidLimits)
    }
    pub(super) fn required_bytes(capacity: usize) -> Result<usize, Error> {
        Self::bucket_count(capacity)?
            .checked_mul(std::mem::size_of::<Bucket>())
            .ok_or(Error::InvalidLimits)
    }
    pub(super) fn new(capacity: usize) -> Result<Self, Error> {
        Ok(Self {
            buckets: allocate(Self::bucket_count(capacity)?, || Bucket {
                hash: 0,
                slot: EMPTY,
            })?,
            deleted: 0,
        })
    }
    pub(super) fn bytes(&self) -> usize {
        self.buckets.capacity() * std::mem::size_of::<Bucket>()
    }
    pub(super) fn find(&self, hash: u64, mut matches: impl FnMut(usize) -> bool) -> Option<usize> {
        let mask = self.buckets.len() - 1;
        for offset in 0..self.buckets.len() {
            let bucket = self.buckets[(hash as usize).wrapping_add(offset) & mask];
            if bucket.slot == EMPTY {
                return None;
            }
            if bucket.slot != DELETED && bucket.hash == hash && matches(bucket.slot) {
                return Some(bucket.slot);
            }
        }
        None
    }
    pub(super) fn insert(&mut self, hash: u64, slot: usize) -> Result<(), Error> {
        let mask = self.buckets.len() - 1;
        for offset in 0..self.buckets.len() {
            let bucket = &mut self.buckets[(hash as usize).wrapping_add(offset) & mask];
            if bucket.slot == EMPTY || bucket.slot == DELETED {
                self.deleted -= usize::from(bucket.slot == DELETED);
                *bucket = Bucket { hash, slot };
                return Ok(());
            }
        }
        Err(Error::ResourceLimit)
    }
    pub(super) fn remove(&mut self, hash: u64, slot: usize) -> Result<(), Error> {
        let mask = self.buckets.len() - 1;
        for offset in 0..self.buckets.len() {
            let bucket = &mut self.buckets[(hash as usize).wrapping_add(offset) & mask];
            if bucket.slot == EMPTY {
                break;
            }
            if bucket.hash == hash && bucket.slot == slot {
                bucket.slot = DELETED;
                self.deleted += 1;
                return Ok(());
            }
        }
        Err(Error::InvalidHandle)
    }
    pub(super) fn needs_compaction(&self) -> bool {
        self.deleted > self.buckets.len() / 4
    }
    pub(super) fn clear(&mut self) {
        self.buckets.fill(Bucket {
            hash: 0,
            slot: EMPTY,
        });
        self.deleted = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collisions_and_deleted_buckets_preserve_other_keys_and_reuse_capacity() {
        let mut index = Index::new(4).unwrap();
        for slot in 0..4 {
            index.insert(u64::MAX, slot).unwrap();
        }
        index.remove(u64::MAX, 1).unwrap();
        assert_eq!(index.find(u64::MAX, |slot| slot == 3), Some(3));
        assert_eq!(index.find(u64::MAX, |slot| slot == 1), None);
        index.insert(u64::MAX, 5).unwrap();
        assert_eq!(index.find(u64::MAX, |slot| slot == 5), Some(5));
        assert_eq!(index.find(11, |_| true), None);
        assert_eq!(index.remove(u64::MAX, 99), Err(Error::InvalidHandle));
    }

    #[test]
    fn full_index_failure_is_bounded_and_compaction_has_no_new_allocation() {
        let mut index = Index::new(4).unwrap();
        let bytes = index.bytes();
        for slot in 0..index.buckets.len() {
            index.insert(0, slot).unwrap();
        }
        assert_eq!(index.insert(0, 99), Err(Error::ResourceLimit));
        assert_eq!(index.find(0, |slot| slot == 99), None);
        for slot in 0..3 {
            index.remove(0, slot).unwrap();
        }
        assert!(index.needs_compaction());
        index.clear();
        assert_eq!(index.find(0, |_| true), None);
        assert!(!index.needs_compaction());
        assert_eq!(index.bytes(), bytes);
        index.insert(0, 99).unwrap();
        assert_eq!(index.find(0, |slot| slot == 99), Some(99));
    }
}
