use std::collections::BTreeSet;
use std::convert::TryInto;
// use std::convert::TryInto;

// use crate::smt::{
// construct_epoch_smt, construct_lock_info_smt, u64_to_h256, TopSmtInfo, BOTTOM_SMT,
// };

use crate::smt::{construct_epoch_smt, construct_propose_count_smt, u64_to_h256, TopSmtInfo};

use super::*;
use axon_types::checkpoint::{CheckpointCellData, ProposeCount, ProposeCounts};
use axon_types::metadata::{Metadata, MetadataArgs, MetadataList, MetadataWitness, StakeSmtElectionInfo};
use ckb_testtool::ckb_crypto::secp::Generator;
// use ckb_testtool::ckb_types::H256;
// use axon_types::stake::*;
// use bit_vec::BitVec;
// use ckb_system_scripts::BUNDLED_CELL;
// use ckb_testtool::ckb_crypto::secp::Generator;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use helper::*;
use molecule::prelude::*;
use util::helper::ProposeCountObject;
// use util::smt::LockInfo;

#[test]
fn test_metadata_success() {
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

    let metadata_args = MetadataArgs::new_builder()
        .metadata_type_id(axon_byte32(&[1u8; 32].pack()))
        .build();
    let metadata_type_script = context
        .build_script(&contract_out_point, Bytes::from(metadata_args.as_bytes()))
        .expect("metadata type script");
    println!(
        "metadata type script: {:?}",
        metadata_type_script.calc_script_hash()
    );
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let keypair = Generator::random_keypair();
    let staker_addr = pubkey_to_addr(&keypair.1.serialize());
    let propose_count = ProposeCount::new_builder()
        .address(axon_byte20(&staker_addr))
        .count(axon_u32(100))
        .build();
    let propose_counts = vec![propose_count];
    let propose_counts = ProposeCounts::new_builder().set(propose_counts).build();
    // prepare checkpoint lock_script
    let checkpoint_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![2]))
        .expect("checkpoint script");
    let checkpoint_data = CheckpointCellData::new_builder()
        .version(0.into())
        .epoch(axon_u64(1))
        .period(axon_u32(100))
        // .latest_block_hash(v)
        .latest_block_height(axon_u64(10))
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        // .propose_count(v)
        .state_root(axon_byte32(&[0u8; 32].pack()))
        .timestamp(axon_u64(11111))
        .propose_count(propose_counts)
        .build();
    // prepare checkpoint cell_dep
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
        .stake_addr(axon_identity_none())
        .build();
    let stake_smt_type_script = context
        .build_script(&contract_out_point, stake_smt_args.as_bytes())
        .expect("stake smt type script");

    // prepare tx inputs and outputs
    let input_stake_infos = BTreeSet::new();
    let input_stake_smt_data =
        axon_stake_smt_cell_data(&input_stake_infos, &metadata_type_script.calc_script_hash());

    // prepare metadata
    let metadata0 = Metadata::new_builder().epoch_len(axon_u32(100)).build();
    let metadata1 = metadata0.clone();
    let metadata2 = metadata0.clone();
    let metadata_list = MetadataList::new_builder()
        .push(metadata0)
        .push(metadata1)
        .push(metadata2)
        .build();
    println!(
        "checkpoint script: {:?}",
        checkpoint_type_script.calc_script_hash()
    );
    let propose_count_smt_root = [0u8; 32];
    let input_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone().calc_script_hash(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script.calc_script_hash(),
        metadata_list.clone(),
        1,
        propose_count_smt_root,
    );

    let inputs = vec![
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
    let outputs = vec![
        // stake smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
        // metadata cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(metadata_type_script.clone()).pack())
            .build(),
    ];

    let output_stake_infos = BTreeSet::new();
    let output_stake_smt_data = axon_stake_smt_cell_data(
        &output_stake_infos,
        &metadata_type_script.calc_script_hash(),
    );
    let propose_count = ProposeCountObject {
        addr: staker_addr,
        count: 100 as u32,
    };
    let propose_infos = vec![propose_count];
    let (propose_count_root, _) = construct_propose_count_smt(&propose_infos);
    println!("propose_count_root: {:?}", propose_count_root);
    let top_smt_info = TopSmtInfo {
        epoch: 1,
        smt_root: propose_count_root,
    };
    let (top_smt_root, proof) = construct_epoch_smt(&vec![top_smt_info]);
    let propose_count_proof = proof.compile(vec![u64_to_h256(1)]).unwrap().0;

    let output_meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone().calc_script_hash(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script.calc_script_hash(),
        metadata_list,
        2,
        top_smt_root.as_slice().try_into().unwrap(),
    );

    let outputs_data = vec![
        output_stake_smt_data.as_bytes(), // stake smt cell
        output_meta_data.as_bytes(),
    ];

    let stake_smt_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(vec![2])).pack())
        .build();

    let stake_smt_election_info = StakeSmtElectionInfo::new_builder()
        .build();
    let metadata_witness = MetadataWitness::new_builder()
        .new_propose_proof(axon_bytes(&propose_count_proof))
        .smt_election_info(stake_smt_election_info)
        .build();
    let metadata_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(metadata_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![metadata_witness.as_bytes().pack(), stake_smt_witness.as_bytes().pack()])
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