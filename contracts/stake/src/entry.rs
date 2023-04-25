// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
use alloc::{
    collections::{btree_map::BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::vec::{Vec, self};

use alloc::vec::{self, Vec};
use ckb_smt::smt::Tree;
use ckb_smt::smt::Pair;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*, packed::CellInput},
    debug,
    high_level::{load_cell_lock_hash, load_script, load_witness_args, load_cell_type_hash},
};

use axon_types::{stake_reader::{self as axon, StakeInfos}, Cursor, metadata::MetadataCellData, stake::StakeInfo, basic_reader::Identity};
use util::{error::Error, helper::*};

pub enum MODE {
    UPDATE,    // update stake entry only
    UPDATESMT, // update stake SMT cell's root
    ELECTION,  // elect validators of next epoch
}

const SMT_TYPE_ID: [u8; 32] = [0u8; 32];

pub fn verify_update_stake_at_cell(staker_identity: &Vec<u8>, stake_at_lock_hash: &[u8; 32]) -> Result<(), Error> {
    debug!("update stake info in stake at cell");
    if !secp256k1::verify_signature(&staker_identity) {
        return Err(Error::SignatureMismatch);
    }

    // extract AT type_id from type_script, or get xudt_type_id of this chain from metadata
    let xudt_type_id = {
        let type_hash = load_cell_type_hash(0, Source::GroupInput)?;
        if type_hash.is_none() {
            return Err(Error::TypeScriptEmpty);
        }
        type_hash.unwrap()
    };
    let input_at_amount = get_sudt_by_type_hash(&xudt_type_id, Source::Input)?;
    let output_at_amount = get_sudt_by_type_hash(&xudt_type_id, Source::Output)?;
    if input_at_amount != output_at_amount {
        return Err(Error::MismatchInputOutputAtAmount);
    }

    let (input_amount, input_stake_at_data) =
        get_stake_at_data_by_lock_hash(&stake_at_lock_hash, Source::Input)?;
    let (output_amount, output_stake_at_data) =
        get_stake_at_data_by_lock_hash(&stake_at_lock_hash, Source::Output)?;
    if input_stake_at_data.version() != output_stake_at_data.version()
        || input_stake_at_data.checkpoint_type_id()
            != output_stake_at_data.checkpoint_type_id()
        || input_stake_at_data.xudt_type_id() != output_stake_at_data.xudt_type_id()
    {
        return Err(Error::UpdateModeError);
    }

    let epoch = get_current_epoch(&input_stake_at_data.checkpoint_type_id())?;

    let input_stake_info = input_stake_at_data.stake_info();
    let input_stake = bytes_to_u128(&input_stake_info.amount());
    let input_increase = input_stake_info.is_increase() == 1;
    let input_inaugutation_epoch = input_stake_info.inauguration_epoch();

    let output_stake_info = output_stake_at_data.stake_info();
    let output_stake = bytes_to_u128(&output_stake_info.amount());
    let output_increase = output_stake_info.is_increase() == 1;
    let output_inaugutation_epoch = input_stake_info.inauguration_epoch();

    if output_inaugutation_epoch != epoch + 2 {
        return Err(Error::BadInaugurationEpoch);
    }

    // let input_stale = input_inaugutation_epoch > 0 && input_inaugutation_epoch < epoch;
    if input_increase {
        if output_increase {
            if output_stake - input_stake != output_amount - input_amount {
                return Err(Error::BadStakeStakeChange);
            }
        } else {
            if input_stake != input_amount - output_amount {
                return Err(Error::BadStakeRedeemChange);
            }
            if output_stake > input_amount {
                return Err(Error::RedeemExceedLimit);
            }
        }
    } else {
        if output_increase {
            if output_stake != output_amount - input_amount {
                return Err(Error::BadStakeChange);
            }
        } else {
            if output_stake > input_amount {
                return Err(Error::RedeemExceedLimit);
            }
        }
    }
}

pub fn verify_2layer_smt(stake_infos: &StakeInfos, epoch: u64, epoch_proof: &Vec<u8>, epoch_root: &[u8])  -> Result<(), Error> {
    // construct old stake smt root & verify
    let mut tree_buf = [Pair::default(); 100];
    let mut tree = Tree::new(&tree_buf);
    for i in 0..stake_infos.len() {
        let stake_info = &stake_infos.get(i);
        tree.update(stake_info.staker(), stake_info.amount()).map_err(|err| {
            debug!("update smt tree error: {}", err);
            Error::MerkleProof
        })?;
    }

    let proof = [0u8; 32];
    let stake_root = tree.calculate_root(&proof)?; // epoch value
    let mut epoch_tree = Tree::new(&tree_buf);
    let checkpoint_type_id = [0u8; 32];
    let epoch = get_current_epoch(checkpoint_type_id)?;
    epoch_tree.update(epoch, &stake_root).map_err(|err| {
        debug!("update smt tree error: {}", err);
        Error::MerkleProof
    })?;
    let epoch_root = [0u8; 32];
    epoch_tree.verify(&epoch_root, &epoch_proof).map_err(|err| {
        debug!(
            "expected target block exists in the main chain: {}",
            err
        );
        Error::OldStakeInfosErr
    })?;
    Ok(())
}

struct StakerAmount {
    addr: Identity,
    amount: u128,
}

pub fn update_by_stake_infos(addr: &Identity, old_stake: u128, stake_infos: &StakeInfos) -> bool {
    for i in 0..stake_infos.len() {
        let stake_info = &stake_infos.get(i);
        if addr == stake_info.addr() {
            old_stake = stake_info.amount();
            return true;
        }
    }
    false
}

pub fn transform_to_map(stake_infos: &StakeInfos) -> BTreeMap<Identity, u128> {
    let stake_infos_map = BTreeMap::new();
    for i in 0..stake_infos.len() {
        let stake_info = &stake_infos.get(i);
        stake_infos_map.insert(stake_info.addr(), stake_info.amount());
    }
    stake_infos_map
}


pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    // extract stake_args
    let stake_args: axon::StakeArgs = Cursor::from(args.to_vec()).into();
    let smt_type_id = stake_args.stake_smt_type_id();
    let staker_identity = stake_args.staker_identity();

    // SMT_TYPE_ID get from metadata? or use xudt_type_id to identity different axon-based chains
    if smt_type_id != SMT_TYPE_ID {
        return Err(Error::MissMatchSmtTypeId);
    }

    // identify contract mode by witness
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let mode = match witness_args {
        Ok(witness) => {
            let value = witness.input_type().to_opt();
            if value.is_none() || value.as_ref().unwrap().len() != 1 {
                return Err(Error::BadWitnessInputType);
            }
            let input_type = *value.unwrap().raw_data().to_vec().first().unwrap();
            if input_type == 0 {
                MODE::UPDATE
            } else if input_type == 1 {
                MODE::UPDATESMT
            } else if input_type == 2 {
                MODE::ELECTION
            } else {
                return Err(Error::UnknownMode);
            }
        }
        Err(_) => {
            return Err(Error::UnknownMode);
        }
    };

    // extract stake at cell lock hash
    let stake_at_lock_hash = { load_cell_lock_hash(0, Source::GroupInput)? };

    match mode {
        MODE::UPDATE => {
            verify_update_stake_at_cell(&staker_identity, &stake_at_lock_hash)?;
        }
        MODE::UPDATESMT => {
            debug!("update smt root mode");
            // stake smt cell
            if staker_identity.is_empty() {
                // get old_stakes & proof from Stake AT cells' witness of input
                let stake_smt_update_infos = {
                    let witness_lock = witness_args.lock().to_opt();
                    if witness_lock.is_none() {
                        return Err(Error::WitnessLockError);
                    }
                    let value: axon::StakeSmtUpdateInfo =
                        Cursor::from(witness_lock.unwrap().raw_data().to_vec()).into();
                    value
                };
                
                // construct old stake smt root & verify
                let checkpoint_type_id = [0u8; 32];
                let epoch = get_current_epoch(checkpoint_type_id)?;
                let old_stakes = BTreeSet::default();
                let stake_infos = stake_smt_update_infos.all_stake_infos();
                let epoch_root = [0u8;32]; // get from input smt cell
                let epoch_proof = stake_smt_update_infos.old_epoch_proof();
                verify_2layer_smt(&stake_infos, epoch, &epoch_proof, &epoch_root)?;

                // get proof of new_stakes from Stake AT cells' witness of input, 
                // verify delete_stakes is zero
                let stake_infos_map = transform_to_map(&stake_infos);
                let stake_at_type_id = [0u8; 32]; // get from type script
                let update_infos = get_stake_update_infos(&stake_at_type_id, Source::GroupInput)?;
                for (addr, stake_info_delta) in update_infos {
                    let inauguration_epoch= stake_info_delta.inauguration_epoch();
                    if inauguration_epoch < epoch + 2 {
                        return Err(Error::StaleStakeInfo);
                    }

                    // after updated to smt cell, the output stake should be reset
                    let (output_amount, output_stake_at_data) =
                    get_stake_at_data_by_lock_hash(&stake_at_lock_hash, Source::Output)?;
                    let output_stake_info = output_stake_at_data.stake_info();
                    let output_stake = bytes_to_u128(&output_stake_info.amount());
                    let output_increase: bool = output_stake_info.is_increase() == 1;
                    let output_inaugutation_epoch = inauguration_epoch;
    
                    if output_stake != 0 || output_increase != 1 || output_stake_info != 0 {
                        return Err(Error::IllegalDefaultStakeInfo);
                    }

                    let old_stake = 0u128;
                    if stake_infos_map.get(addr).is_none() {
                        old_stake = 100; // should be staker's at amount, get from stake at cell
                        stake_infos_map.insert(addr, old_stake);
                    } else {
                        old_stake = stake_infos_map.get(addr).unwrap();
                    }
                    let input_stake = stake_info_delta.amount();
                    let input_increase = stake_info_delta.is_increase();
                    // calculate the stake of output
                    let redeem_amount = 0u128;
                    if input_increase {
                        old_stake += input_stake;
                    } else {
                        if input_stake > old_stake {
                            redeem_amount = old_stake;
                            old_stake = 0;
                        } else {
                            redeem_amount = input_stake;
                            old_stake -= input_stake;                        
                        }
                    }
                    stake_infos_map[addr] = old_stake;

                    // get input & output withdraw AT cell
                    if redeem_amount > 0 {
                        let input_withdraw_amount = 10u128; // get from staker input withdraw at cell
                        let output_withdraw_amount = 10u128; // get from staker input withdraw at cell
                        if output_withdraw_amount - input_withdraw_amount != redeem_amount {
                            return Err(Error::BadRedeem);
                        }
                    }
                }

                // sort stakes by amount
                let mut stake_infos_iter = stake_infos_map.iter().rev();
                let quorum_size = 10;
                let new_stake_infos: Vec<(&Identity, &u128)> = stake_infos_iter.take(3 * quorum_size).collect();

                // get proof of new_stakes from Stake AT cells' witness of input, 
                // verify delete_stakes is zero
                // verify the new stake infos is equal to on-chain calculation
                // let new_stake_infos = StakeInfos { cursor: () };
                let new_epoch_root = [0u8;32]; // get from output smt cell
                let new_epoch_proof = stake_smt_update_infos.new_epoch_proof();
                verify_2layer_smt(&new_stake_infos, epoch, &new_epoch_proof, &new_epoch_root)?;
            } else { // staker AT cell
                // may be only need to verify input and output both contain the Stake SMT cell of the Chain 
                let smt_type_id = vec![0u8; 32];
                let input_smt_cell = get_cell_count(smt_type_id, Source::Input);
                if input_smt_cell != 1 {
                    return Err(Error::BadInputStakeSmtCellCount);
                }
                let output_smt_cell = get_cell_count(smt_type_id, Source::Output);
                if output_smt_cell != 1 {
                    return Err(Error::BadOutputStakeSmtCellCount);
                }
            }
        }
        MODE::ELECTION => {
            // only smt cell is needed 
            if staker_identity.is_empty() {
                // get smt cell data
                let (input_amount, input_stake_at_data) =
                get_stake_at_data_by_lock_hash(&stake_at_lock_hash, Source::Input)?;

                let checkpoint_data =
                get_checkpoint_from_celldeps(&input_stake_at_data.checkpoint_type_id())?;
                let epoch = checkpoint_data.epoch();
                let period = checkpoint_data.period();

                let metadata = MetadataCellData::default();
                // get period_len from metadata cell
                let period_len = metadata.metadata().get(0).unwrap().period_len();
                if period != period_len {
                    return Err(Error::BadElectionTime);
                }

                // get stake & delegate data of epoch n + 1 & n + 2,  from witness of stake smt cell
                let election_info: axon::StakeSmtElectionInfo = axon::StakeSmtElectionInfo;
                let n1 = election_info.n1();
                let miner_infos = n1.miners();
                for i in 0..miner_infos.len() {
                    let miner_info = &miner_infos.get(i);
                    tree.update(miner_info.staker(), miner_info.amount()).expect("update");
                    let delegator_infos = miner_info.delegator_infos();
                    for i in 0..delegator_infos.len() {
                        let delegator_info = &delegator_infos.get(i);
                        tree.update(delegator_info.addr(), delegator_info.amount()).expect("update");
                    }
                    let delegate_root = tree.root();
                    let epoch_proof = miner_info.delegator_epoch_proof();
                    let leaves = vec![epoch, delegate_root]; // epoch is key
                    let epoch_n1_root = H256::default();// get from delegate smt cell
                    let has = epoch_proof.verify::<Blake2bHasher>(epoch_n1_root, leaves).unwrap();
                }

                let stake_root = tree.root(); // construct smt root from all stake infos of epoch n + 1
                let epoch_proof = n1.staker_epoch_proof();
                let leaves = vec![epoch, stake_root]; // epoch is key
                let epoch_n1_root = H256::default();// get from stake smt cell
                let has = epoch_proof.verify::<Blake2bHasher>(epoch_n1_root, leaves).unwrap();
                
                // get proof & verify, must be data of epoch n + 1 & n + 2.
                // rank stakers(stake amount + delegate amount),
                // only keep top quorum stakers as validators, others as delete_stakers & delete_delegators
                // verify validators' stake amount, verify delete_stakers & delete_delegators all zero & withdraw At cell amount is equal.

                // get output metadata, verify the validators are equal.
            }

        }
    }

    Ok(())
}
