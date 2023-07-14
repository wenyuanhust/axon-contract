use std::collections::BTreeSet;
use std::convert::TryFrom;

use crate::smt::{construct_epoch_smt, construct_lock_info_smt, TopSmtInfo};

use super::*;
use axon_types::metadata::{Metadata, MetadataList};
use axon_types::stake::*;
// use bit_vec::BitVec;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::ckb_crypto::secp::Generator;
use ckb_testtool::ckb_types::core::ScriptHashType;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use helper::*;
use molecule::prelude::*;
use ophelia::{Crypto, PrivateKey, Signature, ToPublicKey, UncompressedPublicKey};
use ophelia_secp256k1::{Secp256k1Recoverable, Secp256k1RecoverablePrivateKey};
use util::smt::u64_to_h256;
use util::smt::{new_blake2b, LockInfo, BOTTOM_SMT};

#[test]
fn test_stake_at_increase_success() {
    // init context
    let mut context = Context::default();
    /*
    let secp256k1_data_bin: Bytes = fs::read(
        "/root/git/axon-contract/common/ckb-lib-secp256k1/secp256k1_blake2b_sighash_all_dual",
    )
    .expect("load secp256k1")
    .into();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin);
    let secp256k1_script = context.build_script_with_hash_type(
        &secp256k1_data_out_point,
        ScriptHashType::Data1,
        Bytes::from(vec![2]),
    );
    println!(
        "secp256k1 code hash: {:?}",
        secp256k1_script.unwrap().code_hash().as_slice()
    );
    */
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());

    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
    let contract_bin: Bytes = Loader::default().load_binary("stake");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");
    // println!(
    //     "checkpoint type hash: {:?}",
    //     checkpoint_type_script.calc_script_hash().as_slice()
    // );
    // let stake_at_lock_script = context
    //     .build_script(&always_success_out_point, Bytes::from(vec![3]))
    //     .expect("stake at script");
    let stake_at_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![4]))
        .expect("sudt script");
    let metadata_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![5]),
        )
        .expect("metadata type script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    // eth signature
    let hex_privkey = [0xcd; 32];
    let priv_key = Secp256k1RecoverablePrivateKey::try_from(hex_privkey.as_slice()).unwrap();
    let pubkey = priv_key.pub_key();
    let pubkey = pubkey.to_uncompressed_bytes().to_vec();
    // println!("pubkey: {:?}, len: {:?}", pubkey, pubkey.len());

    // prepare stake_args and stake_data
    println!(
        "metadata_type_script type hash: {:?}",
        metadata_type_script.calc_script_hash().as_slice()
    );
    let stake_args = stake::StakeArgs::new_builder()
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        // .stake_addr(eth_addr(&keypair.1.serialize()))
        .stake_addr(eth_addr(pubkey))
        .build();

    let input_stake_info_delta = stake::StakeInfoDelta::new_builder()
        .is_increase(1.into())
        .amount(axon_u128(0 as u128))
        .inauguration_epoch(axon_u64(0 as u64))
        .build();
    let keypair = Generator::random_keypair();
    // println!("staker pubkey: {:?}", keypair.1.serialize());
    let input_stake_at_data = axon_stake_at_cell_data_without_amount(
        0,
        &keypair.1.serialize(),
        &keypair.1.serialize(),
        &metadata_type_script.calc_script_hash(),
        input_stake_info_delta,
    );

    // prepare stake lock_script
    let stake_at_lock_script = context
        .build_script(&contract_out_point, stake_args.as_bytes())
        .expect("stake script");

    // prepare tx inputs and outputs
    // println!("stake at cell lock hash:{:?}", stake_at_lock_script.calc_script_hash().as_slice());
    let inputs = vec![
        // stake AT cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(stake_at_lock_script.clone())
                        .type_(Some(stake_at_type_script.clone()).pack())
                        .build(),
                    Bytes::from(axon_stake_at_cell_data(0, input_stake_at_data)),
                ),
            )
            .build(),
        // normal AT cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(stake_at_type_script.clone()).pack())
                        .build(),
                    Bytes::from((1000 as u128).to_le_bytes().to_vec()),
                ),
            )
            .build(),
    ];
    let outputs = vec![
        // stake at cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(stake_at_lock_script)
            .type_(Some(stake_at_type_script.clone()).pack())
            .build(),
        // stake cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_at_type_script.clone()).pack())
            .build(),
    ];

    // prepare outputs_data
    let output_stake_info_delta = stake::StakeInfoDelta::new_builder()
        .is_increase(1.into())
        .amount(axon_u128(100 as u128))
        .inauguration_epoch(axon_u64(3 as u64))
        .build();
    let output_stake_at_data = axon_stake_at_cell_data_without_amount(
        0,
        &keypair.1.serialize(),
        &keypair.1.serialize(),
        &metadata_type_script.calc_script_hash(),
        output_stake_info_delta,
    );
    let outputs_data = vec![
        Bytes::from(axon_stake_at_cell_data(100, output_stake_at_data)), // stake at cell
        Bytes::from((900 as u128).to_le_bytes().to_vec()),               // normal at cell
                                                                         // Bytes::from(axon_withdrawal_data(50, 2)),
    ];

    // prepare metadata cell_dep
    let metadata = Metadata::new_builder().epoch_len(axon_u32(100)).build();
    let metadata_list = MetadataList::new_builder().push(metadata).build();
    let meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_at_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_at_type_script, // needless here
        &checkpoint_type_script,
        metadata_list,
        1,
        [0u8; 32],
    );
    let metadata_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(metadata_type_script.clone()).pack())
                    .build(),
                meta_data.as_bytes(),
            ),
        )
        .build();
    // prepare checkpoint cell_dep
    let checkpoint_data = axon_checkpoint_data(&metadata_type_script.clone().calc_script_hash());
    // println!("checkpoint data: {:?}", checkpoint_data.as_bytes().len());
    let checkpoint_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(checkpoint_type_script).pack())
                    .build(),
                checkpoint_data.as_bytes(),
            ),
        )
        .build();

    // let stake_at_witness = StakeAtWitness::new_builder().mode(0.into()).build();
    // println!("stake at witness: {:?}", stake_at_witness.as_bytes().len());
    // let stake_at_witness = WitnessArgs::new_builder()
    //     .lock(Some(Bytes::from(stake_at_witness.as_bytes())).pack())
    //     .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        // .witness(stake_at_witness.as_bytes().pack())
        .cell_dep(contract_dep)
        .cell_dep(always_success_script_dep)
        .cell_dep(secp256k1_data_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(metadata_script_dep)
        .build();

    let msg = tx.hash();
    // println!("tx hash: {:?}", msg.clone().as_bytes().to_vec());
    let signature = Secp256k1Recoverable::sign_message(&msg.as_bytes(), &priv_key.to_bytes())
        .unwrap()
        .to_bytes()
        .to_vec();
    println!(
        "eth_addr msg: {:?}, signature:{:?}, len: {:?}",
        tx.hash(),
        signature,
        signature.len()
    );

    // {
    //     let pubkey: ophelia_secp256k1::Secp256k1RecoverablePublicKey = priv_key.pub_key();
    //     let pubkey = pubkey.to_uncompressed_bytes();
    //     let result = Secp256k1Recoverable::verify_signature(&msg.as_slice(), &signature, &pubkey);
    //     println!(
    //         "secp256k1 signature, signature: {:?}, msg: {:?}, pubkey: {:?}",
    //         signature,
    //         msg.as_slice().to_vec(),
    //         pubkey.to_vec()
    //     );
    //     match result {
    //         Ok(_) => println!("Verify secp256k1 signature success!"),
    //         Err(err) => println!("Verify secp256k1 signature failed! {}", err),
    //     }
    // }

    let stake_at_witness = StakeAtWitness::new_builder()
        .mode(0.into())
        .eth_sig(axon_byte65(signature))
        .build();
    println!("stake at witness: {:?}", stake_at_witness.as_bytes().len());
    let stake_at_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(stake_at_witness.as_bytes())).pack())
        .build();

    let tx = context.complete_tx(tx);
    let tx = sign_eth_tx(tx, stake_at_witness);

    // sign tx for stake at cell (update stake at cell delta mode)
    // let tx = sign_stake_tx(tx, &keypair.0, stake_at_witness);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
pub fn test_stake_withdraw_success() {
    println!("hello");

    // prepare withdraw lock_script
    // let withdrawal_args = axon_types::withdraw::WithdrawArgs::new_builder()
    //     .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
    //     .addr(axon_identity(&vec![0u8; 20]))
    //     .build();
    // let withdrawal_lock_script = Script::new_builder()
    //     .code_hash([0u8; 32].pack())
    //     .hash_type(ScriptHashType::Type.into())
    //     .args(withdrawal_args.as_slice().pack())
    //     .build();

    // withdrawal cell
    // CellOutput::new_builder()
    //     .capacity(1000.pack())
    //     .lock(withdrawal_lock_script.clone())
    //     .type_(Some(stake_at_type_script.clone()).pack())
    //     .build(),
}

#[test]
fn test_stake_smt_success() {
    // init context
    let mut context = Context::default();
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
    let at_contract_bin: Bytes = Loader::default().load_binary("stake");
    let at_contract_out_point = context.deploy_cell(at_contract_bin);
    let at_contract_dep = CellDep::new_builder()
        .out_point(at_contract_out_point.clone())
        .build();
    let smt_contract_bin: Bytes = Loader::default().load_binary("stake-smt");
    let smt_contract_out_point = context.deploy_cell(smt_contract_bin);
    let smt_contract_dep = CellDep::new_builder()
        .out_point(smt_contract_out_point.clone())
        .build();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");

    let stake_at_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![4]))
        .expect("sudt script");
    println!(
        "stake at type hash: {:?}",
        stake_at_type_script.calc_script_hash().as_bytes().to_vec()
    );
    let metadata_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![5]),
        )
        .expect("metadata type script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    // prepare stake_args and stake_data
    let keypair = Generator::random_keypair();
    let stake_at_args = stake::StakeArgs::new_builder()
        .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
        .stake_addr(axon_identity(&keypair.1.serialize()))
        .build();

    let new_stake_amount = 100;
    let inauguration_epoch = 3;
    let input_stake_info_delta = stake::StakeInfoDelta::new_builder()
        .is_increase(1.into())
        .amount(axon_u128(new_stake_amount))
        .inauguration_epoch(axon_u64(inauguration_epoch))
        .build();
    let input_stake_at_data = axon_stake_at_cell_data_without_amount(
        0,
        &keypair.1.serialize(),
        &keypair.1.serialize(),
        &metadata_type_script.calc_script_hash(),
        input_stake_info_delta,
    );

    // prepare stake lock_script
    let stake_at_lock_script = context
        .build_script(&at_contract_out_point, stake_at_args.as_bytes())
        .expect("stake at lock script");

    let stake_smt_type_script = context
        .build_script_with_hash_type(
            &smt_contract_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![6u8; 32]),
        )
        .expect("stake smt type script");
    println!(
        "stake_smt_type_script: {:?}",
        stake_smt_type_script.calc_script_hash().as_bytes().to_vec()
    );

    // prepare tx inputs and outputs
    println!("empty input stake infos of stake smt cell");
    let input_stake_infos = BTreeSet::new();
    let input_stake_smt_data = axon_stake_smt_cell_data(
        &input_stake_infos,
        &metadata_type_script.calc_script_hash(),
        inauguration_epoch,
    );

    let input_stake_smt_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
        input_stake_smt_data.as_bytes(),
    );
    // let stake_smt_input_dep = CellDep::new_builder()
    //     .out_point(input_stake_smt_out_point.clone())
    //     .build();

    let inputs = vec![
        // stake AT cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(stake_at_lock_script.clone())
                        .type_(Some(stake_at_type_script.clone()).pack())
                        .build(),
                    Bytes::from(axon_stake_at_cell_data(100, input_stake_at_data)),
                ),
            )
            .build(),
        // stake smt cell
        CellInput::new_builder()
            .previous_output(
                // context.create_cell(
                //     CellOutput::new_builder()
                //         .capacity(1000.pack())
                //         .lock(always_success_lock_script.clone())
                //         .type_(Some(stake_smt_type_script.clone()).pack())
                //         .build(),
                //     input_stake_smt_data.as_bytes(),
                // ),
                input_stake_smt_out_point,
            )
            .build(),
    ];

    // let output_stake_smt_out_point = context.create_cell(
    //     CellOutput::new_builder()
    //         .capacity(1000.pack())
    //         .lock(always_success_lock_script.clone())
    //         .type_(Some(stake_smt_type_script.clone()).pack())
    //         .build(),
    //     input_stake_smt_data.as_bytes(),
    // );
    // let stake_smt_input_dep = CellDep::new_builder()
    //     .out_point(input_stake_smt_out_point.clone())
    //     .build();

    let outputs = vec![
        // stake at cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(stake_at_lock_script.clone())
            .type_(Some(stake_at_type_script.clone()).pack())
            .build(),
        // stake smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
    ];

    // prepare outputs_data
    let output_stake_info_delta = stake::StakeInfoDelta::new_builder()
        // .is_increase(0.into())
        // .amount(axon_u128(0 as u128))
        // .inauguration_epoch(axon_u64(0 as u64))
        .build();
    let output_stake_at_data = axon_stake_at_cell_data_without_amount(
        0,
        &keypair.1.serialize(),
        &keypair.1.serialize(),
        &metadata_type_script.calc_script_hash(),
        output_stake_info_delta,
    );

    let lock_info = LockInfo {
        addr: blake160(keypair.1.serialize().as_slice()),
        amount: new_stake_amount,
    };
    let output_stake_infos = vec![lock_info].into_iter().collect::<BTreeSet<LockInfo>>();
    // let output_stake_infos = BTreeSet::new();
    let output_stake_smt_data = axon_stake_smt_cell_data(
        &output_stake_infos,
        &metadata_type_script.calc_script_hash(),
        inauguration_epoch,
    );
    println!(
        "output stake smt data: {:?}",
        output_stake_smt_data.as_bytes().len()
    );
    let outputs_data = vec![
        Bytes::from(axon_stake_at_cell_data(100, output_stake_at_data)), // stake at cell
        output_stake_smt_data.as_bytes(),                                // stake smt cell
    ];

    // prepare metadata cell_dep
    let metadata = Metadata::new_builder()
        .epoch_len(axon_u32(100))
        .quorum(axon_u16(2))
        .build();
    let metadata_list = MetadataList::new_builder().push(metadata).build();
    let meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &stake_at_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &stake_smt_type_script,
        metadata_list,
        inauguration_epoch - 2,
        [0u8; 32],
    );
    let metadata_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(metadata_type_script.clone()).pack())
                    .build(),
                meta_data.as_bytes(),
            ),
        )
        .build();
    // prepare checkpoint cell_dep
    let checkpoint_data = axon_checkpoint_data(&metadata_type_script.clone().calc_script_hash());
    println!("checkpoint data: {:?}", checkpoint_data.as_bytes().len());
    let checkpoint_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(checkpoint_type_script).pack())
                    .build(),
                checkpoint_data.as_bytes(),
            ),
        )
        .build();

    // construct old epoch proof
    let bottom_tree = BOTTOM_SMT::default();
    let old_bottom_root = bottom_tree.root();
    let top_smt_infos = vec![TopSmtInfo {
        epoch: inauguration_epoch,
        smt_root: *old_bottom_root,
    }];
    let (_, old_proof) = construct_epoch_smt(&top_smt_infos);
    let old_proof = old_proof
        .compile(vec![u64_to_h256(inauguration_epoch)])
        .unwrap()
        .0;
    println!("old proof: {:?}", old_proof);

    // let lock_info = LockInfo {
    //     addr: blake160(keypair.1.serialize().as_slice()),
    //     amount: 100,
    // };
    let lock_infos: BTreeSet<LockInfo> =
        vec![lock_info].into_iter().collect::<BTreeSet<LockInfo>>();
    let (new_bottom_root, _) = construct_lock_info_smt(&lock_infos);
    let new_top_smt_infos = vec![TopSmtInfo {
        epoch: inauguration_epoch,
        smt_root: new_bottom_root,
    }];
    let (new_top_root, new_proof) = construct_epoch_smt(&new_top_smt_infos);
    let new_proof = new_proof
        .compile(vec![u64_to_h256(inauguration_epoch)])
        .unwrap()
        .0;
    println!(
        "new_bottom_root: {:?}, new_top_root: {:?}, epoch: {}, new proof: {:?}",
        new_bottom_root, new_top_root, inauguration_epoch, new_proof
    );

    let _stake_info = stake::StakeInfo::new_builder()
        .addr(axon_identity(&keypair.1.serialize().as_slice().to_vec()))
        .amount(axon_u128(100))
        .build(); // assume old stake smt is empty
    let stake_infos = stake::StakeInfos::new_builder().build();
    let stake_smt_update_info = stake::StakeSmtUpdateInfo::new_builder()
        .all_stake_infos(stake_infos)
        .old_epoch_proof(axon_bytes(&old_proof))
        .new_epoch_proof(axon_bytes(&new_proof))
        // .old_bottom_proof(axon_bytes_none())
        .build();
    let stake_smt_witness = StakeSmtWitness::new_builder()
        .mode(0.into())
        .update_info(stake_smt_update_info)
        .build();
    let stake_smt_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(stake_smt_witness.as_bytes())).pack())
        .build();

    let stake_at_witness = StakeAtWitness::new_builder().mode(1.into()).build();
    println!("stake at witness: {:?}", stake_at_witness.as_bytes().len());
    let stake_at_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(stake_at_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![
            stake_at_witness.as_bytes().pack(),
            stake_smt_witness.as_bytes().pack(),
        ])
        .cell_dep(at_contract_dep)
        .cell_dep(smt_contract_dep)
        .cell_dep(always_success_script_dep)
        .cell_dep(secp256k1_data_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(metadata_script_dep)
        // .cell_dep(stake_smt_input_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_stake_smt_create_success() {
    // init context
    let mut context = Context::default();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let smt_contract_bin: Bytes = Loader::default().load_binary("stake-smt");
    let smt_contract_out_point = context.deploy_cell(smt_contract_bin);
    let smt_contract_dep = CellDep::new_builder()
        .out_point(smt_contract_out_point.clone())
        .build();

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

    let input_hash = {
        let mut blake2b = new_blake2b();
        blake2b.update(input.as_slice());
        blake2b.update(&0u64.to_le_bytes());
        let mut ret = [0; 32];
        blake2b.finalize(&mut ret);
        Bytes::from(ret.to_vec())
    };
    let stake_smt_type_script = context
        .build_script(&smt_contract_out_point, input_hash)
        .expect("stake smt type script");
    println!(
        "stake_smt_type_script: {:?}",
        stake_smt_type_script.calc_script_hash().as_bytes().to_vec()
    );

    let outputs = vec![
        // stake smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(stake_smt_type_script.clone()).pack())
            .build(),
    ];

    let inauguration_epoch = 3;
    let output_stake_infos = BTreeSet::new();
    let output_stake_smt_data = axon_stake_smt_cell_data(
        &output_stake_infos,
        &always_success_lock_script.calc_script_hash(),
        inauguration_epoch,
    );
    println!(
        "output stake smt data: {:?}",
        output_stake_smt_data.as_bytes().len()
    );
    let outputs_data = vec![
        output_stake_smt_data.as_bytes(), // stake smt cell
    ];

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(smt_contract_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_stake_election_success() {
    // init context
    let mut context = Context::default();

    let contract_bin: Bytes = Loader::default().load_binary("stake-smt");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("checkpoint script");
    println!(
        "checkpoint type hash: {:?}",
        checkpoint_type_script.calc_script_hash().as_slice()
    );

    let metadata_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![5]),
        )
        .expect("metadata type script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    // prepare stake lock_script
    // let stake_smt_args = stake::StakeArgs::new_builder()
    //     .metadata_type_id(axon_byte32(&metadata_type_script.calc_script_hash()))
    //     // .stake_addr(axon_identity_none())
    //     .build();
    let stake_smt_type_script = context
        .build_script_with_hash_type(
            &contract_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![6u8; 32]),
        )
        .expect("stake smt type script");

    // prepare tx inputs and outputs
    let inauguration_epoch = 3;
    let input_stake_infos = BTreeSet::new();
    let input_stake_smt_data = axon_stake_smt_cell_data(
        &input_stake_infos,
        &metadata_type_script.calc_script_hash(),
        inauguration_epoch,
    );

    // prepare metadata cell_dep
    let metadata = Metadata::new_builder().epoch_len(axon_u32(100)).build();
    let metadata_list = MetadataList::new_builder().push(metadata).build();
    let meta_data = axon_metadata_data(
        &metadata_type_script.clone().calc_script_hash(),
        &stake_smt_type_script.calc_script_hash(),
        &checkpoint_type_script.calc_script_hash(),
        &stake_smt_type_script.calc_script_hash(),
        metadata_list,
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
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(metadata_type_script.clone()).pack())
                        .build(),
                    meta_data.as_bytes(),
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
        inauguration_epoch,
    );
    let outputs_data = vec![
        output_stake_smt_data.as_bytes(), // stake smt cell
        meta_data.as_bytes(),
    ];

    let stake_smt_witness = StakeSmtWitness::new_builder().mode(1.into()).build();
    let stake_smt_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(stake_smt_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![stake_smt_witness.as_bytes().pack()])
        .cell_dep(contract_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
