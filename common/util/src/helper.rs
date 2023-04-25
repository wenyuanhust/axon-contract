extern crate alloc;

use crate::error::Error;
use alloc::{
    collections::{btree_map::BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use axon_types::{checkpoint_reader, stake_reader, Cursor, basic::Identity, stake_reader::StakeInfoDelta};
use ckb_std::{
    ckb_constants::Source,
    high_level::{load_cell_data, load_cell_type_hash, QueryIter, load_cell_lock_hash},
};

pub fn bytes_to_u128(bytes: &Vec<u8>) -> u128 {
    let mut array: [u8; 16] = [0u8; 16];
    array.copy_from_slice(bytes.as_slice());
    u128::from_le_bytes(array)
}

pub fn get_checkpoint_from_celldeps(
    checkpoint_type_hash: &Vec<u8>,
) -> Result<checkpoint_reader::CheckpointLockCellData, Error> {
    let mut checkpoint_data = None;
    QueryIter::new(load_cell_type_hash, Source::CellDep)
        .enumerate()
        .for_each(|(i, type_hash)| {
            if type_hash.unwrap_or([0u8; 32]) == checkpoint_type_hash.as_slice() {
                assert!(checkpoint_data.is_none());
                checkpoint_data = {
                    let data = load_cell_data(i, Source::CellDep).unwrap();
                    let checkpoint_data: checkpoint_reader::CheckpointLockCellData =
                        Cursor::from(data).into();
                    Some(checkpoint_data)
                };
            }
        });
    if checkpoint_data.is_none() {
        return Err(Error::CheckpointDataEmpty);
    }
    Ok(checkpoint_data.unwrap())
}

pub fn get_current_epoch(
    checkpoint_type_id: &Vec<u8>,
) -> Result<u64, Error> {
    let mut checkpoint_data = None;
    QueryIter::new(load_cell_type_hash, Source::CellDep)
        .enumerate()
        .for_each(|(i, type_hash)| {
            if type_hash.unwrap_or([0u8; 32]) == checkpoint_type_id.as_slice() {
                assert!(checkpoint_data.is_none());
                checkpoint_data = {
                    let data = load_cell_data(i, Source::CellDep).unwrap();
                    let checkpoint_data: checkpoint_reader::CheckpointLockCellData =
                        Cursor::from(data).into();
                    Some(checkpoint_data)
                };
            }
        });
    if checkpoint_data.is_none() {
        return Err(Error::CheckpointDataEmpty);
    }
    Ok(checkpoint_data.unwrap().epoch())
}

pub fn get_sudt_by_type_hash(type_hash: &Vec<u8>, source: Source) -> Result<u128, Error> {
    let mut sudt = 0u128;
    QueryIter::new(load_cell_type_hash, source)
        .enumerate()
        .map(|(i, cell_type_hash)| {
            if cell_type_hash.unwrap_or([0u8; 32]) == type_hash[..] {
                let data = load_cell_data(i, source).unwrap();
                if data.len() < 16 {
                    return Err(Error::BadSudtDataFormat);
                }
                sudt += bytes_to_u128(&data[..16].to_vec());
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(sudt)
}

pub fn get_stake_at_data_by_lock_hash(
    cell_lock_hash: &[u8; 32],
    source: Source,
) -> Result<(u128, stake_reader::StakeAtCellData), Error> {
    let mut sudt = None;
    let mut stake_at_data = None;
    QueryIter::new(load_cell_type_hash, source)
        .enumerate()
        .for_each(|(i, lock_hash)| {
            if &lock_hash.unwrap_or([0u8; 32]) == cell_lock_hash {
                let data = load_cell_data(i, source).unwrap();
                if data.len() >= 16 {
                    sudt = Some(bytes_to_u128(&data[..16].to_vec()));
                    assert!(stake_at_data.is_none());
                    stake_at_data = {
                        let stake_data: stake_reader::StakeAtCellData =
                            Cursor::from(data[16..].to_vec()).into();
                        Some(stake_data)
                    };
                }
            }
        });
    if sudt.is_none() {
        return Err(Error::BadSudtDataFormat);
    }
    if stake_at_data.is_none() {
        return Err(Error::StakeDataEmpty);
    }
    Ok((sudt.unwrap(), stake_at_data.unwrap()))
}

pub fn get_stake_update_infos(
    cell_type_hash: &[u8; 32],
    source: Source,
) -> Result<Vec<(Identity, StakeInfoDelta)>, Error> {
    let mut stake_update_infos = Vec::<(Identity, StakeInfoDelta)>::default();
    QueryIter::new(load_cell_type_hash, source)
        .enumerate()
        .for_each(|(i, type_hash)| {
            if &type_hash.unwrap_or([0u8; 32]) == cell_type_hash {
                let data = load_cell_data(i, source).unwrap();
                let stake_at_data = {
                    let stake_data: stake_reader::StakeAtCellData =
                        Cursor::from(data[16..].to_vec()).into();
                    Some(stake_data)
                };
                let stake_info = stake_at_data.unwrap().stake_info();
                let address = Identity::default(); // get from lock_script
                stake_update_infos.push((address, stake_info));
            }
        });

    Ok(stake_update_infos)
}

pub fn get_cell_count(type_id: Vec<u8>, source: Source) -> u8 {
    let mut cells_count = 0u8;
    QueryIter::new(load_cell_lock_hash, source).for_each(|lock_hash| {
        if &lock_hash == type_id.as_slice() {
            cells_count += 1;
        }
    });
    cells_count
}

// pub fn verify_2layer_smt(stake_proof: MerkleProof, stake_root: H256, staker_identity: Vec<u8>, old_stake: u128,
//                          epoch_proof: MerkleProof, epoch_root: H256, epoch: u64) -> Result<(), Error> {
//     if verify_smt(stake_proof, &stake_root, staker_identity.to_h256(), old_stake.to_h256()) {
//         return Err(Error::IllegalInputStakeInfo);
//     }

//     if verify_smt(epoch_proof, &epoch_root, epoch.to_h256(), stake_root) {
//         Err(Error::IllegalInputStakeInfo)
//     } else {
//         Ok(())
//     }
// }

// pub fn verify_smt(proof: MerkleProof, root: &H256, key: H256, value: H256) -> bool {
//     let leaves = vec![(key, value)];
//     proof.verify::<Blake2bHasher>(root, leaves).unwrap()
// }
