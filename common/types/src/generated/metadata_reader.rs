#![allow(dead_code)]
#![allow(unused_imports)]
extern crate alloc;
use alloc::vec::Vec;
use molecule2::Cursor;

use super::basic::*;
pub struct Validator {
    pub cursor: Cursor,
}

impl From<Cursor> for Validator {
    fn from(cursor: Cursor) -> Self {
        Validator { cursor }
    }
}

impl Validator {
    pub fn bls_pub_key(&self) -> Vec<u8> {
        let cur = self.cursor.table_slice_by_index(0).unwrap();
        cur.into()
    }
}

impl Validator {
    pub fn pub_key(&self) -> Vec<u8> {
        let cur = self.cursor.table_slice_by_index(1).unwrap();
        cur.into()
    }
}

impl Validator {
    pub fn address(&self) -> Vec<u8> {
        let cur = self.cursor.table_slice_by_index(2).unwrap();
        cur.into()
    }
}

impl Validator {
    pub fn propose_weight(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(3).unwrap();
        cur.into()
    }
}

impl Validator {
    pub fn vote_weight(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(4).unwrap();
        cur.into()
    }
}

impl Validator {
    pub fn propose_count(&self) -> u64 {
        let cur = self.cursor.table_slice_by_index(5).unwrap();
        cur.into()
    }
}

pub struct ValidatorHistory {
    pub cursor: Cursor,
}

impl From<Cursor> for ValidatorHistory {
    fn from(cursor: Cursor) -> Self {
        ValidatorHistory { cursor }
    }
}

impl ValidatorHistory {
    pub fn address(&self) -> Vec<u8> {
        let cur = self.cursor.table_slice_by_index(0).unwrap();
        cur.into()
    }
}

impl ValidatorHistory {
    pub fn propose_count(&self) -> u64 {
        let cur = self.cursor.table_slice_by_index(1).unwrap();
        cur.into()
    }
}

pub struct MetadataList {
    pub cursor: Cursor,
}

impl From<Cursor> for MetadataList {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}

impl MetadataList {
    pub fn len(&self) -> usize {
        self.cursor.dynvec_length()
    }
}

impl MetadataList {
    pub fn get(&self, index: usize) -> Metadata {
        let cur = self.cursor.dynvec_slice_by_index(index).unwrap();
        cur.into()
    }
}

pub struct ValidatorList {
    pub cursor: Cursor,
}

impl From<Cursor> for ValidatorList {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}

impl ValidatorList {
    pub fn len(&self) -> usize {
        self.cursor.dynvec_length()
    }
}

impl ValidatorList {
    pub fn get(&self, index: usize) -> Validator {
        let cur = self.cursor.dynvec_slice_by_index(index).unwrap();
        cur.into()
    }
}

pub struct ValidatorHistoryList {
    pub cursor: Cursor,
}

impl From<Cursor> for ValidatorHistoryList {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}

impl ValidatorHistoryList {
    pub fn len(&self) -> usize {
        self.cursor.dynvec_length()
    }
}

impl ValidatorHistoryList {
    pub fn get(&self, index: usize) -> ValidatorHistory {
        let cur = self.cursor.dynvec_slice_by_index(index).unwrap();
        cur.into()
    }
}

pub struct Metadata {
    pub cursor: Cursor,
}

impl From<Cursor> for Metadata {
    fn from(cursor: Cursor) -> Self {
        Metadata { cursor }
    }
}

impl Metadata {
    pub fn epoch_len(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(0).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn period_len(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(1).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn quorum(&self) -> u16 {
        let cur = self.cursor.table_slice_by_index(2).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn gas_limit(&self) -> u64 {
        let cur = self.cursor.table_slice_by_index(3).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn gas_price(&self) -> u64 {
        let cur = self.cursor.table_slice_by_index(4).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn interval(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(5).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn validators(&self) -> ValidatorList {
        let cur = self.cursor.table_slice_by_index(6).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn propose_ratio(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(7).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn prevote_ratio(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(8).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn precommit_ratio(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(9).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn brake_ratio(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(10).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn tx_num_limit(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(11).unwrap();
        cur.into()
    }
}

impl Metadata {
    pub fn max_tx_size(&self) -> u32 {
        let cur = self.cursor.table_slice_by_index(12).unwrap();
        cur.into()
    }
}

pub struct MetadataCellData {
    pub cursor: Cursor,
}

impl From<Cursor> for MetadataCellData {
    fn from(cursor: Cursor) -> Self {
        MetadataCellData { cursor }
    }
}

impl MetadataCellData {
    pub fn version(&self) -> u8 {
        let cur = self.cursor.table_slice_by_index(0).unwrap();
        cur.into()
    }
}

impl MetadataCellData {
    pub fn epoch(&self) -> u64 {
        let cur = self.cursor.table_slice_by_index(1).unwrap();
        cur.into()
    }
}

impl MetadataCellData {
    pub fn metadata(&self) -> MetadataList {
        let cur = self.cursor.table_slice_by_index(2).unwrap();
        cur.into()
    }
}

impl MetadataCellData {
    pub fn validators_history(&self) -> ValidatorHistoryList {
        let cur = self.cursor.table_slice_by_index(3).unwrap();
        cur.into()
    }
}
