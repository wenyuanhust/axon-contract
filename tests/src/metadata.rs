use crate::delegate::TestDelegateInfo;
use crate::smt::{
    construct_epoch_smt, construct_epoch_smt_for_metadata_update, construct_lock_info_smt,
    construct_propose_count_smt, TopSmtInfo,
};
use std::collections::BTreeSet;
use std::convert::TryInto;

use super::*;
use axon_types::checkpoint::{CheckpointCellData, ProposeCount, ProposeCounts};
use axon_types::metadata::{
    DelegateInfo, DelegateProof, DelegateProofs, ElectionSmtProof, Metadata, MetadataArgs,
    MetadataList, MetadataWitness, MinerGroupInfo, MinerGroupInfos, StakeSmtElectionInfo,
    Validator, ValidatorList,
};
use axon_types::metadata_reader::MetadataCellData;
use axon_types::withdraw::WithdrawArgs;
use axon_types::Cursor;
use ckb_testtool::ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_testtool::ckb_types::core::ScriptHashType;
use ckb_testtool::ckb_types::{self, h256};
use ckb_testtool::ckb_types::{
    bytes::Bytes, core::TransactionBuilder, core::TransactionView, packed::*, prelude::*,
};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};

use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    traits::{
        default_impls::{
            DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
            DefaultTransactionDependencyProvider,
        },
        CellCollector, CellQueryOptions, Signer,
    },
};

use helper::*;
use molecule::prelude::*;
use util::error::Error::MetadataNotLastCheckpoint;
use util::helper::{bytes_to_u128, ProposeCountObject};
use util::smt::{u64_to_h256, LockInfo};

#[test]
fn test_calc_type_id() {
    let tx_hash = h256!("0xf2039e169030e4f3ed5ea860fe34926d35b1129f66c2d5bd26bf50b86cea879e");
    let previous_output = OutPoint::new(tx_hash.pack(), 0);
    let input = CellInput::new_builder()
        .previous_output(previous_output)
        .build();

    let new_metadata_type_id = calc_type_id(&input, 0);
    println!("new_metadata_type_id: {:#x}", new_metadata_type_id);
}

#[test]
fn test_metadata_parse() {
    let ckb_rpc = "https://testnet.ckb.dev/rpc";
    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);

    // Define the type script
    let code_hash = Byte32::from_slice(
        &hex::decode("2c8f63ac17c1e5e660dddbf49e88994cd1c49d4d6e99e7a7fd3f8879700d3cd1").unwrap(),
    )
    .unwrap();
    let hash_type = ckb_types::core::ScriptHashType::Type.into();
    let args =
        hex::decode("db0782aba62896c2a7c279f3de8dbbd7fd06729cc8b7b499df93f5c450f61839").unwrap();
    println!("args len: {:x?}", args);
    let metadata_cell_type_script = ckb_types::packed::Script::new_builder()
        .code_hash(code_hash)
        .hash_type(hash_type)
        .args(Bytes::from(args).pack())
        .build();

    let query = CellQueryOptions::new_type(metadata_cell_type_script);
    let (more_infos, more_capacity) = cell_collector.collect_live_cells(&query, true).unwrap();
    println!("cell: {}, cap: {}", more_infos.len(), more_capacity);

    let cell_data = more_infos[0].output_data.clone();
    let metadata: Option<MetadataCellData> = Some(Cursor::from(cell_data[..].to_vec()).into());
    match metadata {
        Some(metadata) => {
            let base_reward = metadata.base_reward();
            // let base_reward = Cursor::from(base_reward).into();
            println!("base reward: {:?}", bytes_to_u128(&base_reward));
            let propose_minimum_rate = metadata.propose_minimum_rate();
            println!("propose_minimum_rate: {}", propose_minimum_rate);
            let metadatalist = metadata.metadata();
            let metadata0 = metadatalist.get(0);
            let validatorlist = metadata0.validators();
            println!("validatorlist len {}", validatorlist.len());
            let validator = validatorlist.get(0);
            let bls_pub_key = validator.bls_pub_key();
            println!("bls_pub_key: {:x?}", bls_pub_key);
        }
        None => println!("fail"),
    }
}

#[test]
fn test_metadata_cell_data() {
    let validator_list = get_validator_list();
    let metadata0 = Metadata::new_builder()
        .epoch_len(axon_u32(100))
        .quorum(axon_u16(2))
        .validators(validator_list)
        .build();
    let metadata1 = metadata0.clone();
    let metadata_list = MetadataList::new_builder()
        .push(metadata0)
        .push(metadata1)
        .build();

    let metadata_type_script = Script::new_builder().build();
    let output_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &metadata_type_script.calc_script_hash(),
        &metadata_type_script,
        &metadata_type_script,
        &metadata_type_script,
        metadata_list,
        2,
        100,
        100,
        [0u8; 32],
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
    );

    println!("output_data: {:?}", output_meta_data);
    // let output_data = output_meta_data.as_slice();
    // let output_data: String = output_data
    //     .iter()
    //     .map(|byte| format!("{:02x}", byte))
    //     .collect();
    // println!("output_data: 0x{}", output_data);
}

pub fn hex_decode(src: &str) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }

    let src = if src.starts_with("0x") {
        src.split_at(2).1
    } else {
        src
    };

    let src = src.as_bytes();
    let mut ret = vec![0u8; src.len() / 2];
    faster_hex::hex_decode(src, &mut ret).unwrap();

    ret
}
/*
[[params.verifier_list]]
bls_pub_key = "0xa26e3fe1cf51bd4822072c61bdc315ac32e3d3c2e2484bb92942666399e863b4bf56cf2926383cc706ffc15dfebc85c6"
pub_key = "0x031ddc35212b7fc7ff6685b17d91f77c972535aee5c7ae5684d3e72b986f08834b"
address = "0x8ab0cf264df99d83525e9e11c7e4db01558ae1b1"
propose_weight = 1
vote_weight = 1

[[params.verifier_list]]
bls_pub_key = "0x80310fa9df724b5603d283b472ed3bf85254a8a4ceda8a274b421f6cf2be1d9184267cdfe9a199d36ff14e57668a55d0"
pub_key = "0x02b77c74eb68af3d4d6cc7884ed6709f1a2a1af0f713382a4438ec2ea3a70d4d7f"
address = "0xf386573563c3a75dbbd269fce9782620826ddac2"
propose_weight = 1
vote_weight = 1

[[params.verifier_list]]
bls_pub_key = "0x897721e9016864141a8b982a48217f66ef318ce598aa31842cddaaebe3cd7feab17050022afa6c2123aba39938fe4142"
pub_key = "0x027ffd6a6a231561f2afe5878b1c743323b34263d16787130b1815fe35649b0bf5"
address = "0x8af204ac5d7cb8815a6c53a50b72d01e729d3b22"
propose_weight = 1
vote_weight = 1

[[params.verifier_list]]
bls_pub_key = "0x98eef09a3927acb225191101a1d9aa85775fdcdc87b9ba36898f6c132b485d66aef91c0f51cda331be4f985c3be6761c"
pub_key = "0x0232c489c23b1207107e9a24648c1e4754a8c1c0b38db96df57a526201035058cb"
address = "0xf4cc1652dcec2e5de9ce6fb1b6f9fa9456e957f1"
propose_weight = 1
vote_weight = 1
 */
pub fn get_validator_list() -> ValidatorList {
    let mut valiators = Vec::new();
    {
        let bls_pub_key: [u8; 48] = hex_decode("0xa26e3fe1cf51bd4822072c61bdc315ac32e3d3c2e2484bb92942666399e863b4bf56cf2926383cc706ffc15dfebc85c6").try_into().unwrap();
        let pub_key =
            hex_decode("0x031ddc35212b7fc7ff6685b17d91f77c972535aee5c7ae5684d3e72b986f08834b");
        let address: [u8; 20] = hex_decode("0x8ab0cf264df99d83525e9e11c7e4db01558ae1b1")
            .try_into()
            .unwrap();
        println!("bls: {:x?}, {}", bls_pub_key, bls_pub_key.len(),);

        let validator0 = Validator::new_builder()
            .bls_pub_key(axon_array48_byte48([0u8; 48]))
            .pub_key(axon_byte33(pub_key))
            .address(axon_byte20_identity(&address))
            .build();

        valiators.push(validator0);
    }
    {
        let bls_pub_key: [u8; 48] = hex_decode("0x80310fa9df724b5603d283b472ed3bf85254a8a4ceda8a274b421f6cf2be1d9184267cdfe9a199d36ff14e57668a55d0").try_into().unwrap();
        let pub_key =
            hex_decode("0x02b77c74eb68af3d4d6cc7884ed6709f1a2a1af0f713382a4438ec2ea3a70d4d7f");
        let address: [u8; 20] = hex_decode("0xf386573563c3a75dbbd269fce9782620826ddac2")
            .try_into()
            .unwrap();
        println!("bls: {:x?}, {}", bls_pub_key, bls_pub_key.len(),);

        let validator1 = Validator::new_builder()
            .bls_pub_key(axon_array48_byte48([0u8; 48]))
            .pub_key(axon_byte33(pub_key))
            .address(axon_byte20_identity(&address))
            .build();

        valiators.push(validator1);
    }
    {
        let bls_pub_key: [u8; 48] = hex_decode("0x897721e9016864141a8b982a48217f66ef318ce598aa31842cddaaebe3cd7feab17050022afa6c2123aba39938fe4142").try_into().unwrap();
        let pub_key =
            hex_decode("0x027ffd6a6a231561f2afe5878b1c743323b34263d16787130b1815fe35649b0bf5");
        let address: [u8; 20] = hex_decode("0x8af204ac5d7cb8815a6c53a50b72d01e729d3b22")
            .try_into()
            .unwrap();
        println!("bls: {:x?}, {}", bls_pub_key, bls_pub_key.len(),);

        let validator2 = Validator::new_builder()
            .bls_pub_key(axon_array48_byte48([0u8; 48]))
            .pub_key(axon_byte33(pub_key))
            .address(axon_byte20_identity(&address))
            .build();

        valiators.push(validator2);
    }
    {
        let bls_pub_key: [u8; 48] = hex_decode("0x98eef09a3927acb225191101a1d9aa85775fdcdc87b9ba36898f6c132b485d66aef91c0f51cda331be4f985c3be6761c").try_into().unwrap();
        let pub_key =
            hex_decode("0x0232c489c23b1207107e9a24648c1e4754a8c1c0b38db96df57a526201035058cb");
        let address: [u8; 20] = hex_decode("0xf4cc1652dcec2e5de9ce6fb1b6f9fa9456e957f1")
            .try_into()
            .unwrap();
        println!("bls: {:x?}, {}", bls_pub_key, bls_pub_key.len(),);

        let validator3 = Validator::new_builder()
            .bls_pub_key(axon_array48_byte48([0u8; 48]))
            .pub_key(axon_byte33(pub_key))
            .address(axon_byte20_identity(&address))
            .build();

        valiators.push(validator3);
    }

    let validator_list = ValidatorList::new_builder().set(valiators).build();

    validator_list
}

#[test]
fn test_metadata_creation_success() {
    // init context
    let mut context = Context::default();

    let contract_bin: Bytes = Loader::default().load_binary("metadata");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");

    let input = CellInput::new_builder()
        .previous_output(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(500.pack())
                    .lock(always_success_lock_script.clone())
                    .build(),
                Bytes::new(),
            ),
        )
        .build();

    let input_hash = calc_type_id(&input, 0);
    let metadata_type_script = context
        .build_script_with_hash_type(&contract_out_point, ScriptHashType::Type, input_hash)
        .expect("metadata type script");
    println!(
        "metadata type script: {:?}",
        metadata_type_script.calc_script_hash().as_bytes().to_vec()
    );
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let keypair = Generator::random_keypair();
    let staker_addr = pubkey_to_addr(&keypair.1.serialize());
    // prepare checkpoint lock_script
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");
    let checkpoint_data = CheckpointCellData::new_builder().build();
    // prepare checkpoint cell_dep
    let checkpoint_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(checkpoint_type_script.clone()).pack())
                    .build(),
                checkpoint_data.as_bytes(),
            ),
        )
        .build();

    // prepare tx inputs and outputs
    // prepare metadata
    let metadata0 = Metadata::new_builder()
        .epoch_len(axon_u32(100))
        .quorum(axon_u16(2))
        .build();
    let metadata1 = metadata0.clone();
    let metadata_list = MetadataList::new_builder()
        .push(metadata0)
        .push(metadata1)
        .build();
    println!(
        "checkpoint script: {:?}",
        checkpoint_type_script.calc_script_hash()
    );

    let inputs = vec![input];
    let outputs = vec![
        // metadata cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(metadata_type_script.clone()).pack())
            .build(),
    ];

    let propose_count = ProposeCountObject {
        addr: staker_addr,
        count: 100 as u64,
    };
    let propose_infos = vec![propose_count];
    let (propose_count_root, _) = construct_propose_count_smt(&propose_infos);
    println!("propose_count_root: {:?}", propose_count_root);
    let top_smt_info = TopSmtInfo {
        epoch: 1,
        smt_root: propose_count_root,
    };
    let (top_smt_root, _proof) = construct_epoch_smt(&vec![top_smt_info]);

    let output_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &metadata_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &metadata_type_script,
        &metadata_type_script,
        metadata_list,
        2,
        100,
        100,
        top_smt_root.as_slice().try_into().unwrap(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
    );

    let outputs_data = vec![output_meta_data.as_bytes()];

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(contract_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[derive(Clone)]
struct TestStakeInfo {
    keypair: (Privkey, Pubkey),
    propose_count: u64,
    amount: u128,
    delegators: BTreeSet<LockInfo>,
}

fn construct_metadata_tx(
    context: &mut Context,
    stakes: Vec<TestStakeInfo>,
    epoch_len: u32,
    period: u32,
) -> TransactionView {
    let current_epoch = 0;
    // let epoch_len = 100;
    // let period: u32 = epoch_len - 1;
    let input_waiting_epoch = current_epoch + 2;
    let output_quasi_epoch = input_waiting_epoch;

    let stake0 = stakes[0].clone();
    let contract_bin: Bytes = Loader::default().load_binary("metadata");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();

    let metadata_args = MetadataArgs::new_builder()
        .metadata_type_id(axon_byte32(&[1u8; 32].pack()))
        .build();
    let metadata_type_script = context
        .build_script_with_hash_type(
            &contract_out_point,
            ScriptHashType::Type,
            Bytes::from(metadata_args.as_bytes()),
        )
        .expect("metadata type script");
    println!(
        "metadata type script: {:?}",
        metadata_type_script.calc_script_hash()
    );
    let special_keypair = stake0.keypair.clone(); // stake0 will be deleted and withdraw
    let delete_delegator = stake0.delegators.first();
    let mut propose_counts = Vec::new();
    let mut propose_count_objs = Vec::new();
    let mut input_stake_infos = BTreeSet::new();
    let mut miner_group_infos = Vec::new();
    let mut new_delegate_proofs = Vec::new();
    let mut output_stake_infos = BTreeSet::new();
    let stake_len = stakes.len();
    for stake in stakes {
        let staker_addr = pubkey_to_addr(&stake.keypair.1.serialize());
        let propose_count = ProposeCount::new_builder()
            .address(axon_byte20(&staker_addr))
            .count(axon_u64(stake.propose_count))
            .build();
        propose_counts.push(propose_count);

        let propose_count_obj = ProposeCountObject {
            addr: staker_addr,
            count: stake.propose_count,
        };
        propose_count_objs.push(propose_count_obj);

        let input_stake_info = LockInfo {
            addr: staker_addr,
            amount: stake.amount,
        };
        input_stake_infos.insert(input_stake_info);

        let (_, input_delegate_epoch_proof) =
            delegate_2layer_smt_root_proof(input_waiting_epoch, &stake.delegators);

        let mut delegate_infos = Vec::new();
        for delegator in &stake.delegators {
            let delegate_info = DelegateInfo::new_builder()
                .addr(axon_byte20_identity(&delegator.addr))
                .amount(axon_u128(delegator.amount))
                .build();
            delegate_infos.push(delegate_info);
        }
        let input_delegate_infos = axon_types::metadata::DelegateInfos::new_builder()
            .set(delegate_infos)
            .build();
        let miner_group_info = MinerGroupInfo::new_builder()
            .staker(axon_identity(&stake.keypair.1.serialize()))
            .amount(axon_u128(stake.amount))
            .delegate_epoch_proof(axon_bytes(&input_delegate_epoch_proof.0))
            .delegate_infos(input_delegate_infos)
            .build();
        miner_group_infos.push(miner_group_info);

        let (_, new_delegate_proof) = delegate_2layer_smt_root_proof_for_metadata_update(
            input_waiting_epoch,
            &stake.delegators,
        );
        let new_delegate_proof = DelegateProof::new_builder()
            .staker(axon_identity(&stake.keypair.1.serialize()))
            .proof(axon_bytes(&new_delegate_proof.0))
            .build();
        new_delegate_proofs.push(new_delegate_proof);

        if stake_len == 3 && stake.amount <= 1000 {
            println!("deleted staker {:?}, amount: {}", staker_addr, stake.amount);
        } else {
            output_stake_infos.insert(LockInfo {
                addr: staker_addr,
                amount: stake.amount,
            });
        }
    }

    let propose_counts = ProposeCounts::new_builder().set(propose_counts).build();
    println!("output_stake_infos: {:?}", output_stake_infos);
    let miner_group_infos = MinerGroupInfos::new_builder()
        .set(miner_group_infos)
        .build();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let (delegate_smt_cell_data, _input_delegate_epoch_proof) = axon_delegate_smt_cell_data(
        &stake0.delegators,
        &metadata_type_script.calc_script_hash(),
        &stake0.keypair.1,
        input_waiting_epoch,
    );

    // prepare checkpoint lock_script
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");
    println!(
        "checkpoint script: {:?}",
        checkpoint_type_script.calc_script_hash()
    );
    let checkpoint_data = CheckpointCellData::new_builder()
        .version(0.into())
        .epoch(axon_u64(current_epoch))
        .period(axon_u32(period))
        // .latest_block_hash(v)
        .latest_block_height(axon_u64(10))
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        .state_root(axon_byte32(&[0u8; 32].pack()))
        .timestamp(axon_u64(11111))
        .propose_count(propose_counts)
        .build();
    // println!("checkpoint data: {:?}", checkpoint_data.as_bytes().len());
    let checkpoint_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(checkpoint_type_script.clone()).pack())
                    .build(),
                checkpoint_data.as_bytes(),
            ),
        )
        .build();

    // prepare stake smt lock_script
    let stake_smt_args = axon_types::stake::StakeArgs::new_builder()
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        // .stake_addr(axon_identity_none())
        .build();
    let stake_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            stake_smt_args.as_bytes(),
        )
        .expect("stake smt type script");

    let delegate_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![1]),
        )
        .expect("delegate smt type script");

    // prepare tx inputs and outputs
    let input_stake_smt_data = axon_stake_smt_cell_data(
        &input_stake_infos,
        &metadata_type_script.calc_script_hash(),
        input_waiting_epoch,
    );

    // prepare metadata
    let input_metadata0 = Metadata::new_builder()
        .epoch_len(axon_u32(epoch_len))
        .quorum(axon_u16(2))
        .build();
    let input_metadata1 = input_metadata0.clone();
    let input_metadata_list = MetadataList::new_builder()
        .push(input_metadata0)
        .push(input_metadata1.clone())
        .build();
    let withdraw_lock_args = WithdrawArgs::new_builder()
        .addr(axon_identity(&special_keypair.1.serialize()))
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        .build();
    let withdraw_lock_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            withdraw_lock_args.as_bytes(),
        )
        .expect("withdraw lock script");
    println!(
        "withdraw_lock_script code hash: {:?}, addr: {:?}, metadata_type_id: {:?}, args: {:?}, withdraw_lock_hash: {:?}",
        withdraw_lock_script.code_hash().as_slice(),
        pubkey_to_addr(&special_keypair.1.serialize()),
        metadata_type_script.calc_script_hash().as_slice(),
        withdraw_lock_args.as_slice(),
        withdraw_lock_script.calc_script_hash().as_slice(),
    );

    let propose_count_smt_root = [0u8; 32];
    let input_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &delegate_smt_type_script,
        input_metadata_list.clone(),
        current_epoch,
        100,
        100,
        propose_count_smt_root,
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &withdraw_lock_script.code_hash(),
    );

    let stake_at_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![4]))
        .expect("sudt script");

    let mut inputs = vec![
        // stake smt cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(stake_smt_type_script.clone()).pack())
                        .build(),
                    input_stake_smt_data.as_bytes(),
                ),
            )
            .build(),
        // delegate smt cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(delegate_smt_type_script.clone()).pack())
                        .build(),
                    delegate_smt_cell_data.as_bytes(),
                ),
            )
            .build(),
        // metadata cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(metadata_type_script.clone()).pack())
                        .build(),
                    input_meta_data.as_bytes(),
                ),
            )
            .build(),
    ];

    let mut outputs = vec![
        // stake smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
        // delegate smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(delegate_smt_type_script.clone()).pack())
            .build(),
        // metadata cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(metadata_type_script.clone()).pack())
            .build(),
    ];

    if stake_len == 3 {
        let input_withdraw_infos = vec![
            (input_waiting_epoch - 2 as u64, 0 as u128),
            (input_waiting_epoch - 1, 0),
            (input_waiting_epoch, 0),
        ];

        let input_withdraw_data = axon_withdraw_at_cell_data_without_amount(input_withdraw_infos);
        let input_withdraw_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
            Bytes::from(axon_withdraw_at_cell_data(0, input_withdraw_data.clone())), // delegate at cell
        );

        let withdraw_lock_args_delete_delegator = WithdrawArgs::new_builder()
            .addr(axon_byte20_identity(&delete_delegator.unwrap().addr))
            .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
            .build();
        let withdraw_lock_script_delete_delegator = context
            .build_script_with_hash_type(
                &always_success_out_point,
                ScriptHashType::Type,
                withdraw_lock_args_delete_delegator.as_bytes(),
            )
            .expect("withdraw lock script");
        let input_withdraw_out_point_delete_delegator = context.create_cell(
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script_delete_delegator.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
            Bytes::from(axon_withdraw_at_cell_data(0, input_withdraw_data)), // delegate at cell
        );
        inputs.push(
            // withdraw at cell
            CellInput::new_builder()
                .previous_output(input_withdraw_out_point)
                .build(),
        );
        inputs.push(
            // withdraw at cell
            CellInput::new_builder()
                .previous_output(input_withdraw_out_point_delete_delegator)
                .build(),
        );

        outputs.push(
            // withdraw at cell
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
        );
        outputs.push(
            // withdraw at cell
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script_delete_delegator.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
        );
    }

    let output_stake_smt_data = axon_stake_smt_cell_data_for_update_metadata_cell(
        &output_stake_infos,
        &metadata_type_script.calc_script_hash(),
        output_quasi_epoch,
    );

    let (propose_count_root, _) = construct_propose_count_smt(&propose_count_objs);
    println!("propose_count_root: {:?}", propose_count_root);
    let top_smt_info = TopSmtInfo {
        epoch: current_epoch,
        smt_root: propose_count_root,
    };
    let (top_smt_root, proof) = construct_epoch_smt(&vec![top_smt_info]);
    let propose_count_proof = proof
        .compile(vec![u64_to_h256(current_epoch + 1)])
        .unwrap()
        .0;

    let output_metadata0 = input_metadata1.clone();
    let output_metadata1 = output_metadata0.clone();
    let metadata_list = MetadataList::new_builder()
        .push(output_metadata0)
        .push(output_metadata1)
        .build();
    let output_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &delegate_smt_type_script,
        metadata_list,
        current_epoch + 1,
        100,
        100,
        top_smt_root.as_slice().try_into().unwrap(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &withdraw_lock_script.code_hash(),
    );

    // assume only 1 staker has delegator
    let output_delegate_infos = stake0.delegators.clone();
    let (output_delegate_smt_cell_data, _out_delegate_epoch_proof) =
        axon_delegate_smt_cell_data_for_metadata_update(
            &output_delegate_infos,
            &metadata_type_script.calc_script_hash(),
            &stake0.keypair.1, // only one delegator for 1st staker in stakes
            input_waiting_epoch,
        );

    let mut outputs_data = vec![
        output_stake_smt_data.as_bytes(), // stake smt cell
        output_delegate_smt_cell_data.as_bytes(),
        output_meta_data.as_bytes(),
    ];
    if stake_len == 3 {
        let withdraw_amount = 1000; // stake0 stake amount
        let output_withdraw_infos = vec![
            (current_epoch, 0 as u128),
            (current_epoch + 1, 0),
            (current_epoch + 2, withdraw_amount),
        ];
        let output_withdraw_data = axon_withdraw_at_cell_data_without_amount(output_withdraw_infos);

        let output_withdraw_infos = vec![
            (current_epoch, 0 as u128),
            (current_epoch + 1, 0),
            (current_epoch + 2, delete_delegator.unwrap().amount),
        ];
        let output_withdraw_data_delete_delegator =
            axon_withdraw_at_cell_data_without_amount(output_withdraw_infos);
        outputs_data.push(Bytes::from(axon_withdraw_at_cell_data(
            withdraw_amount,
            output_withdraw_data,
        )));
        outputs_data.push(Bytes::from(axon_withdraw_at_cell_data(
            delete_delegator.unwrap().amount,
            output_withdraw_data_delete_delegator,
        )));
    }

    let stake_smt_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(vec![2])).pack())
        .build();

    let (stake_root, _stake_proof) = construct_lock_info_smt(&input_stake_infos);
    let stake_top_smt_infos = vec![TopSmtInfo {
        epoch: input_waiting_epoch,
        smt_root: stake_root,
    }];
    let (_stake_root, staker_epoch_proof) = construct_epoch_smt(&stake_top_smt_infos);
    let staker_epoch_proof = staker_epoch_proof
        .compile(vec![u64_to_h256(input_waiting_epoch)])
        .unwrap()
        .0;

    let (_stake_root, out_staker_epoch_proof) =
        construct_epoch_smt_for_metadata_update(&stake_top_smt_infos);
    let out_staker_epoch_proof = out_staker_epoch_proof
        .compile(vec![
            u64_to_h256(input_waiting_epoch),
            u64_to_h256(input_waiting_epoch + 1),
        ])
        .unwrap()
        .0;

    let election_smt_proof = ElectionSmtProof::new_builder()
        .staker_epoch_proof(axon_bytes(&staker_epoch_proof))
        .miners(miner_group_infos)
        .build();

    let new_delegate_proofs = DelegateProofs::new_builder()
        .set(new_delegate_proofs)
        .build();
    let new_stake_proof = out_staker_epoch_proof;
    let stake_smt_election_info = StakeSmtElectionInfo::new_builder()
        .n2(election_smt_proof)
        .new_stake_proof(axon_bytes(&new_stake_proof))
        .new_delegate_proofs(new_delegate_proofs)
        .build();
    let metadata_witness = MetadataWitness::new_builder()
        .new_propose_proof(axon_bytes(&propose_count_proof))
        .smt_election_info(stake_smt_election_info)
        .build();
    let metadata_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(metadata_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![
            stake_smt_witness.as_bytes().pack(),
            Bytes::default().pack(),
            metadata_witness.as_bytes().pack(),
        ])
        .cell_dep(contract_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);
    tx
}

#[test]
fn test_metadata_success_1staker_0delegator() {
    // init context
    let mut context = Context::default();

    let delegators1 = BTreeSet::<LockInfo>::new();
    let stake1 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 2000,
        delegators: delegators1,
    };

    let stakes = vec![stake1];
    let tx = construct_metadata_tx(&mut context, stakes, 100, 99);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_metadata_fail_wrong_period() {
    // init context
    let mut context = Context::default();

    let delegators1 = BTreeSet::<LockInfo>::new();
    let stake1 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 2000,
        delegators: delegators1,
    };

    let stakes = vec![stake1];
    let tx = construct_metadata_tx(&mut context, stakes, 100, 98);
    // run
    let err = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("MetadataNotLastCheckpoint");
    assert_script_error(err, MetadataNotLastCheckpoint as i8);
}

#[test]
fn test_metadata_success_2stakers() {
    // init context
    let mut context = Context::default();

    let delegator_keypair = Generator::random_keypair();
    let delegator0 = LockInfo {
        addr: pubkey_to_addr(&delegator_keypair.1.serialize()),
        amount: 200,
    };
    let mut delegators0 = BTreeSet::<LockInfo>::new();
    delegators0.insert(delegator0);
    let stake0 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 1000,
        delegators: delegators0,
    };

    let delegators1 = BTreeSet::<LockInfo>::new();
    let stake1 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 2000,
        delegators: delegators1,
    };

    let stakes = vec![stake0, stake1];
    let tx = construct_metadata_tx(&mut context, stakes, 100, 99);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_metadata_success_3stakers() {
    // only 2 will be selected
    // init context
    let mut context = Context::default();

    let delegator_keypair = Generator::random_keypair();
    let delegator0 = LockInfo {
        addr: pubkey_to_addr(&delegator_keypair.1.serialize()),
        amount: 200,
    };
    let mut delegators0 = BTreeSet::<LockInfo>::new();
    delegators0.insert(delegator0);
    let stake0 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 1000,
        delegators: delegators0,
    };

    let delegators1 = BTreeSet::<LockInfo>::new();
    let stake1 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 2000,
        delegators: delegators1,
    };

    let delegators2 = BTreeSet::<LockInfo>::new();
    let stake2 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 3000,
        delegators: delegators2,
    };

    let stakes = vec![stake0, stake1, stake2];
    let tx = construct_metadata_tx(&mut context, stakes, 100, 99);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_metadata_success_3stakers_1delegator_1validaor() {
    // only 2 will be selected
    // init context
    let mut context = Context::default();

    let delegator_keypair = Generator::random_keypair();
    let delegator0 = LockInfo {
        addr: pubkey_to_addr(&delegator_keypair.1.serialize()),
        amount: 10,
    };
    let mut delegators0 = BTreeSet::<LockInfo>::new();
    delegators0.insert(delegator0);
    let stake0 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 10,
        delegators: delegators0.clone(),
    };

    let delegators1 = delegators0.clone();
    let stake1 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 20,
        delegators: delegators1,
    };

    let delegators2 = delegators0.clone();
    let stake2 = TestStakeInfo {
        keypair: Generator::random_keypair(),
        propose_count: 100,
        amount: 30,
        delegators: delegators2,
    };

    let in_stakes = vec![stake0.clone(), stake1.clone(), stake2.clone()];

    let delete_miners = vec![
        LockInfo {
            addr: pubkey_to_addr(&stake0.keypair.1.serialize()),
            amount: 10,
        },
        LockInfo {
            addr: pubkey_to_addr(&stake1.keypair.1.serialize()),
            amount: 20,
        },
        LockInfo {
            addr: delegator0.addr,
            amount: 10 + 10,
        },
    ];

    let out_stakes = vec![stake2];

    let tx = construct_metadata_tx_3stakers_1delegator_1validaor(
        &mut context,
        in_stakes,
        out_stakes,
        delete_miners,
        100,
        99,
    );
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

fn construct_metadata_tx_3stakers_1delegator_1validaor(
    context: &mut Context,
    in_stakes: Vec<TestStakeInfo>,
    out_stakes: Vec<TestStakeInfo>,
    delete_miners: Vec<LockInfo>,
    epoch_len: u32,
    period: u32,
) -> TransactionView {
    let current_epoch = 0;
    let input_waiting_epoch = current_epoch + 2;
    let output_quasi_epoch = input_waiting_epoch;

    let contract_bin: Bytes = Loader::default().load_binary("metadata");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();

    let metadata_args = MetadataArgs::new_builder()
        .metadata_type_id(axon_byte32(&[1u8; 32].pack()))
        .build();
    let metadata_type_script = context
        .build_script_with_hash_type(
            &contract_out_point,
            ScriptHashType::Type,
            Bytes::from(metadata_args.as_bytes()),
        )
        .expect("metadata type script");
    println!(
        "metadata type script: {:?}",
        metadata_type_script.calc_script_hash()
    );
    let mut propose_counts = Vec::new();
    let mut propose_count_objs = Vec::new();
    let mut input_stake_infos = BTreeSet::new();
    let mut miner_group_infos = Vec::new();
    let mut new_delegate_proofs = Vec::new();
    let mut output_stake_infos = BTreeSet::new();
    let mut input_test_delegate_infos = Vec::new();

    for stake in in_stakes {
        let staker_addr = pubkey_to_addr(&stake.keypair.1.serialize());
        let propose_count = ProposeCount::new_builder()
            .address(axon_byte20(&staker_addr))
            .count(axon_u64(stake.propose_count))
            .build();
        propose_counts.push(propose_count);

        let propose_count_obj = ProposeCountObject {
            addr: staker_addr,
            count: stake.propose_count,
        };
        propose_count_objs.push(propose_count_obj);

        let input_stake_info = LockInfo {
            addr: staker_addr,
            amount: stake.amount,
        };
        input_stake_infos.insert(input_stake_info);

        let (_, input_delegate_epoch_proof) =
            delegate_2layer_smt_root_proof(input_waiting_epoch, &stake.delegators.clone());

        input_test_delegate_infos.push(TestDelegateInfo {
            staker: staker_addr,
            staker_keypair: stake.keypair.clone(),
            delegates: stake.delegators.clone(),
        });

        let mut delegate_infos = Vec::new();
        for delegator in &stake.delegators {
            let delegate_info = DelegateInfo::new_builder()
                .addr(axon_byte20_identity(&delegator.addr))
                .amount(axon_u128(delegator.amount))
                .build();
            delegate_infos.push(delegate_info);
        }
        let input_delegate_infos = axon_types::metadata::DelegateInfos::new_builder()
            .set(delegate_infos)
            .build();
        let miner_group_info = MinerGroupInfo::new_builder()
            .staker(axon_identity(&stake.keypair.1.serialize()))
            .amount(axon_u128(stake.amount))
            .delegate_epoch_proof(axon_bytes(&input_delegate_epoch_proof.0))
            .delegate_infos(input_delegate_infos)
            .build();
        miner_group_infos.push(miner_group_info);

        let (_, new_delegate_proof) = delegate_2layer_smt_root_proof_for_metadata_update(
            input_waiting_epoch,
            &stake.delegators,
        );
        let new_delegate_proof = DelegateProof::new_builder()
            .staker(axon_identity(&stake.keypair.1.serialize()))
            .proof(axon_bytes(&new_delegate_proof.0))
            .build();
        new_delegate_proofs.push(new_delegate_proof);
    }

    let propose_counts = ProposeCounts::new_builder().set(propose_counts).build();
    println!("output_stake_infos: {:?}", output_stake_infos);
    let miner_group_infos = MinerGroupInfos::new_builder()
        .set(miner_group_infos)
        .build();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let input_delegate_smt_cell_data = axon_delegate_smt_cell_data_multiple(
        &input_test_delegate_infos,
        &metadata_type_script.calc_script_hash(),
        input_waiting_epoch,
    );

    // prepare checkpoint lock_script
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");
    println!(
        "checkpoint script: {:?}",
        checkpoint_type_script.calc_script_hash()
    );
    let checkpoint_data = CheckpointCellData::new_builder()
        .version(0.into())
        .epoch(axon_u64(current_epoch))
        .period(axon_u32(period))
        // .latest_block_hash(v)
        .latest_block_height(axon_u64(10))
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        .state_root(axon_byte32(&[0u8; 32].pack()))
        .timestamp(axon_u64(11111))
        .propose_count(propose_counts)
        .build();
    // println!("checkpoint data: {:?}", checkpoint_data.as_bytes().len());
    let checkpoint_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(checkpoint_type_script.clone()).pack())
                    .build(),
                checkpoint_data.as_bytes(),
            ),
        )
        .build();

    // prepare stake smt lock_script
    let stake_smt_args = axon_types::stake::StakeArgs::new_builder()
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        .build();
    let stake_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            stake_smt_args.as_bytes(),
        )
        .expect("stake smt type script");

    let delegate_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![1]),
        )
        .expect("delegate smt type script");

    // prepare tx inputs and outputs
    let input_stake_smt_data = axon_stake_smt_cell_data(
        &input_stake_infos,
        &metadata_type_script.calc_script_hash(),
        input_waiting_epoch,
    );

    // prepare metadata
    let input_metadata0 = Metadata::new_builder()
        .epoch_len(axon_u32(epoch_len))
        .quorum(axon_u16(1))
        .build();
    let input_metadata1 = input_metadata0.clone();
    let input_metadata_list = MetadataList::new_builder()
        .push(input_metadata0)
        .push(input_metadata1.clone())
        .build();

    let withdraw_lock_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![5u8]),
        )
        .expect("withdraw lock script");
    let propose_count_smt_root = [0u8; 32];
    let input_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &delegate_smt_type_script,
        input_metadata_list.clone(),
        current_epoch,
        100,
        100,
        propose_count_smt_root,
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &withdraw_lock_script.code_hash(),
    );

    let stake_at_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![4]))
        .expect("sudt script");

    let mut inputs = vec![
        // stake smt cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(stake_smt_type_script.clone()).pack())
                        .build(),
                    input_stake_smt_data.as_bytes(),
                ),
            )
            .build(),
        // delegate smt cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(delegate_smt_type_script.clone()).pack())
                        .build(),
                    input_delegate_smt_cell_data.as_bytes(),
                ),
            )
            .build(),
        // metadata cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(metadata_type_script.clone()).pack())
                        .build(),
                    input_meta_data.as_bytes(),
                ),
            )
            .build(),
    ];

    let mut outputs = vec![
        // stake smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
        // delegate smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(delegate_smt_type_script.clone()).pack())
            .build(),
        // metadata cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(metadata_type_script.clone()).pack())
            .build(),
    ];

    let mut out_test_delegate_infos = Vec::new();
    for out_stake in out_stakes {
        output_stake_infos.insert(LockInfo {
            addr: pubkey_to_addr(&out_stake.keypair.1.serialize()),
            amount: out_stake.amount,
        });
        out_test_delegate_infos.push(TestDelegateInfo {
            staker: pubkey_to_addr(&out_stake.keypair.1.serialize()),
            staker_keypair: out_stake.keypair,
            delegates: out_stake.delegators,
        })
    }
    let output_stake_smt_data = axon_stake_smt_cell_data_for_update_metadata_cell(
        &output_stake_infos,
        &metadata_type_script.calc_script_hash(),
        output_quasi_epoch,
    );

    let (propose_count_root, _) = construct_propose_count_smt(&propose_count_objs);
    println!("propose_count_root: {:?}", propose_count_root);
    let top_smt_info = TopSmtInfo {
        epoch: current_epoch,
        smt_root: propose_count_root,
    };
    let (top_smt_root, proof) = construct_epoch_smt(&vec![top_smt_info]);
    let propose_count_proof = proof
        .compile(vec![u64_to_h256(current_epoch + 1)])
        .unwrap()
        .0;

    let output_metadata0 = input_metadata1.clone();
    let output_metadata1 = output_metadata0.clone();
    let metadata_list = MetadataList::new_builder()
        .push(output_metadata0)
        .push(output_metadata1)
        .build();
    let output_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &delegate_smt_type_script,
        metadata_list,
        current_epoch + 1,
        100,
        100,
        top_smt_root.as_slice().try_into().unwrap(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &withdraw_lock_script.code_hash(),
    );

    let output_delegate_smt_cell_data = axon_delegate_smt_cell_data_multiple_for_metadata_update(
        &out_test_delegate_infos,
        &metadata_type_script.calc_script_hash(),
        input_waiting_epoch,
    );

    let mut outputs_data = vec![
        output_stake_smt_data.as_bytes(), // stake smt cell
        output_delegate_smt_cell_data.as_bytes(),
        output_meta_data.as_bytes(),
    ];

    for miner in delete_miners {
        let withdraw_lock_args = WithdrawArgs::new_builder()
            .addr(axon_byte20_identity(&miner.addr))
            .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
            .build();
        let withdraw_lock_script = context
            .build_script_with_hash_type(
                &always_success_out_point,
                ScriptHashType::Type,
                withdraw_lock_args.as_bytes(),
            )
            .expect("withdraw lock script");
        println!(
            "withdraw_lock_script code hash: {:?}, addr: {:?}, metadata_type_id: {:?}, args: {:?}, withdraw_lock_hash: {:?}",
            withdraw_lock_script.code_hash().as_slice(),
            miner.addr,
            metadata_type_script.calc_script_hash().as_slice(),
            withdraw_lock_args.as_slice(),
            withdraw_lock_script.calc_script_hash().as_slice(),
        );

        let input_withdraw_infos = vec![
            (input_waiting_epoch - 2 as u64, 0 as u128),
            (input_waiting_epoch - 1, 0),
            (input_waiting_epoch, 0),
        ];

        let input_withdraw_data = axon_withdraw_at_cell_data_without_amount(input_withdraw_infos);
        let input_withdraw_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
            Bytes::from(axon_withdraw_at_cell_data(0, input_withdraw_data.clone())), // delegate at cell
        );

        inputs.push(
            // withdraw at cell
            CellInput::new_builder()
                .previous_output(input_withdraw_out_point)
                .build(),
        );

        outputs.push(
            // withdraw at cell
            CellOutput::new_builder()
                .capacity(1000.pack())
                .lock(withdraw_lock_script.clone())
                .type_(Some(stake_at_type_script.clone()).pack())
                .build(),
        );

        let output_withdraw_infos = vec![
            (current_epoch, 0 as u128),
            (current_epoch + 1, 0),
            (current_epoch + 2, miner.amount),
        ];
        let output_withdraw_data = axon_withdraw_at_cell_data_without_amount(output_withdraw_infos);

        outputs_data.push(Bytes::from(axon_withdraw_at_cell_data(
            miner.amount,
            output_withdraw_data,
        )));
    }

    let stake_smt_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(vec![2])).pack())
        .build();

    let (stake_root, _stake_proof) = construct_lock_info_smt(&input_stake_infos);
    let stake_top_smt_infos = vec![TopSmtInfo {
        epoch: input_waiting_epoch,
        smt_root: stake_root,
    }];
    let (_stake_root, staker_epoch_proof) = construct_epoch_smt(&stake_top_smt_infos);
    let staker_epoch_proof = staker_epoch_proof
        .compile(vec![u64_to_h256(input_waiting_epoch)])
        .unwrap()
        .0;

    let (_stake_root, out_staker_epoch_proof) =
        construct_epoch_smt_for_metadata_update(&stake_top_smt_infos);
    let out_staker_epoch_proof = out_staker_epoch_proof
        .compile(vec![
            u64_to_h256(input_waiting_epoch),
            u64_to_h256(input_waiting_epoch + 1),
        ])
        .unwrap()
        .0;

    let election_smt_proof = ElectionSmtProof::new_builder()
        .staker_epoch_proof(axon_bytes(&staker_epoch_proof))
        .miners(miner_group_infos)
        .build();

    let new_delegate_proofs = DelegateProofs::new_builder()
        .set(new_delegate_proofs)
        .build();
    let new_stake_proof = out_staker_epoch_proof;
    let stake_smt_election_info = StakeSmtElectionInfo::new_builder()
        .n2(election_smt_proof)
        .new_stake_proof(axon_bytes(&new_stake_proof))
        .new_delegate_proofs(new_delegate_proofs)
        .build();
    let metadata_witness = MetadataWitness::new_builder()
        .new_propose_proof(axon_bytes(&propose_count_proof))
        .smt_election_info(stake_smt_election_info)
        .build();
    let metadata_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(metadata_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![
            stake_smt_witness.as_bytes().pack(),
            Bytes::default().pack(),
            metadata_witness.as_bytes().pack(),
        ])
        .cell_dep(contract_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);
    tx
}
