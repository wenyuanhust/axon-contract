use std::collections::BTreeSet;
use std::convert::TryInto;
use std::iter::FromIterator;

use super::*;
use axon_types::checkpoint::CheckpointCellData;
use axon_types::delegate::DelegateInfoDeltas;
use axon_types::metadata::MetadataList;
use axon_types::reward::{
    EpochRewardStakeInfo, EpochRewardStakeInfos, NotClaimInfo, RewardDelegateInfos,
    RewardSmtCellData, RewardStakeInfo, RewardStakeInfos, RewardWitness,
};
use ckb_testtool::ckb_crypto::secp::Generator;
use ckb_testtool::ckb_types::core::ScriptHashType;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use helper::*;
use molecule::prelude::*;
use sparse_merkle_tree::{blake2b::Blake2bHasher, CompiledMerkleProof, H256};
use util::smt::{
    addr_to_h256, u128_to_h256, u64_to_h256, BottomValue, EpochValue, LockInfo, ProposeBottomValue,
    BOTTOM_SMT, CLAIM_SMT, PROPOSE_BOTTOM_SMT, TOP_SMT,
};

#[test]
fn test_reward_creation_success() {
    // init context
    let mut context = Context::default();

    let contract_bin: Bytes = Loader::default().load_binary("reward");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let reward_cell_data = RewardSmtCellData::new_builder()
        .version(0.into())
        .claim_smt_root(axon_array32_byte32([0u8; 32]))
        .build();
    // prepare tx inputs and outputs
    let input = CellInput::new_builder()
        .previous_output(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .build(),
                reward_cell_data.as_bytes(),
            ),
        )
        .build();

    let input_hash = get_input_hash(&input);
    let reward_type_script = context
        .build_script(&contract_out_point, input_hash)
        .expect("always_success script");

    let outputs = vec![
        // metadata cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(reward_type_script.clone()).pack())
            .build(),
    ];

    let outputs_data = vec![reward_cell_data.as_bytes()];

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
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

#[test]
fn test_reward_success() {
    // init context
    let mut context = Context::default();

    let contract_bin: Bytes = Loader::default().load_binary("reward");
    let contract_out_point = context.deploy_cell(contract_bin);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .build();

    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    let metadata_type_script = context
        .build_script_with_hash_type(
            &contract_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![2]),
        )
        .expect("metadata type script");
    println!(
        "metadata_type_script: {:?}",
        metadata_type_script.calc_script_hash()
    );

    let input0 = CellInput::new_builder()
        .previous_output(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .build(),
                Bytes::from(vec![0u8; 32]),
            ),
        )
        .build();
    let input_hash = get_input_hash(&input0);
    let reward_type_script = context
        .build_script(&contract_out_point, input_hash)
        .expect("reward type script");

    let keypair = Generator::random_keypair();
    let staker_addr = pubkey_to_addr(&keypair.1.serialize());
    // prepare checkpoint lock_script
    let checkpoint_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![3]),
        )
        .expect("checkpoint script");
    // epoch must be 3(no small than 2), so that the reward of epoch 0 can be claimed
    let current_epoch = 3 as u64;
    let checkpoint_data = CheckpointCellData::new_builder()
        .epoch(axon_u64(current_epoch))
        .build();
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
    let stake_amount = 1000;
    let stake_infos = BTreeSet::from_iter(vec![LockInfo {
        addr: staker_addr,
        amount: stake_amount,
    }]);
    let claim_epoch = current_epoch - 3; // claim epoch must be at least 2 epoch before current epoch, here is 0
    let stake_smt_data = axon_stake_smt_cell_data(
        &stake_infos,
        &metadata_type_script.calc_script_hash(),
        claim_epoch,
    );
    let stake_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![4]),
        )
        .expect("stake smt type script");
    let stake_smt_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(stake_smt_type_script.clone()).pack())
                    .build(),
                stake_smt_data.as_bytes(),
            ),
        )
        .build();

    let delegate_infos = BTreeSet::new();
    let (delegate_smt_cell_data, delegate_epoch_proof) = axon_delegate_smt_cell_data(
        &delegate_infos,
        &metadata_type_script.calc_script_hash(),
        &keypair.1,
        claim_epoch,
    );
    let delegate_smt_type_script = context
        .build_script_with_hash_type(
            &always_success_out_point,
            ScriptHashType::Type,
            Bytes::from(vec![5]),
        )
        .expect("delegate smt type script");
    let delegate_smt_script_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .type_(Some(delegate_smt_type_script.clone()).pack())
                    .build(),
                delegate_smt_cell_data.as_bytes(),
            ),
        )
        .build();

    let at_type_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![6]))
        .expect("sudt script");
    // prepare metadata
    let metadata_list = MetadataList::new_builder().build();

    let propose_count = 1000;
    let mut propose_count_smt_bottom_tree = PROPOSE_BOTTOM_SMT::default();
    propose_count_smt_bottom_tree
        .update(
            addr_to_h256(&staker_addr),
            ProposeBottomValue(propose_count),
        )
        .expect("update propose count smt bottom tree");
    let propose_count_smt_bottom_proof = propose_count_smt_bottom_tree
        .merkle_proof(vec![addr_to_h256(&staker_addr)])
        .unwrap();
    let propose_count_smt_bottom_proof = propose_count_smt_bottom_proof
        .compile(vec![addr_to_h256(&staker_addr)])
        .unwrap()
        .0;
    println!(
        "verify propose count smt bottom proof: {:?}, bottom root: {:?}, staker: {:?}, count: {:?}, epoch: {}",
        propose_count_smt_bottom_proof,
        propose_count_smt_bottom_tree.root(),
        staker_addr,
        propose_count,
        claim_epoch
    );

    let mut propose_count_smt_top_tree = TOP_SMT::default();
    let propose_count_smt_bottom_tree_root = propose_count_smt_bottom_tree.root();
    propose_count_smt_top_tree
        .update(
            u64_to_h256(claim_epoch),
            *propose_count_smt_bottom_tree_root,
        )
        .expect("update propose count smt top tree");
    let propose_count_smt_top_proof = propose_count_smt_top_tree
        .merkle_proof(vec![u64_to_h256(claim_epoch)])
        .unwrap();
    let propose_count_smt_top_proof = propose_count_smt_top_proof
        .compile(vec![u64_to_h256(claim_epoch)])
        .unwrap()
        .0;
    let propose_count_smt_top_tree_root = propose_count_smt_top_tree.root();

    let meta_data = axon_metadata_data_by_script(
        &metadata_type_script.clone(),
        &at_type_script.calc_script_hash(),
        &checkpoint_type_script,
        &stake_smt_type_script,
        &delegate_smt_type_script,
        metadata_list.clone(),
        current_epoch,
        propose_count_smt_top_tree_root
            .as_slice()
            .try_into()
            .unwrap(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
        &metadata_type_script.code_hash(),
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

    let old_claim_tree = CLAIM_SMT::default();
    let old_claim_proof = old_claim_tree
        .merkle_proof(vec![addr_to_h256(&staker_addr)])
        .unwrap();
    let old_claim_proof = old_claim_proof
        .compile(vec![addr_to_h256(&staker_addr)])
        .unwrap()
        .0;
    let old_not_claim_info = NotClaimInfo::new_builder()
        .epoch(axon_u64(0))
        .proof(axon_bytes(&old_claim_proof))
        .build();
    println!(
        "old_not_claim_info: {:?}, old claim tree root: {:?}",
        old_not_claim_info,
        old_claim_tree.root()
    );
    let input_reward_smt_data = axon_reward_smt_data(
        metadata_type_script
            .calc_script_hash()
            .as_slice()
            .try_into()
            .unwrap(),
        old_claim_tree.root().as_slice().try_into().unwrap(),
    );
    let inputs = vec![
        input0,
        // reward smt cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(1000.pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(reward_type_script.clone()).pack())
                        .build(),
                    input_reward_smt_data.as_bytes(),
                ),
            )
            .build(),
    ];

    let outputs = vec![
        // reward smt cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(reward_type_script.clone()).pack())
            .build(),
        // normal at cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(at_type_script.clone()).pack())
            .build(),
    ];

    let output_delegate_info_deltas: DelegateInfoDeltas = DelegateInfoDeltas::new_builder().build();
    let output_delegate_at_data = axon_delegate_at_cell_data_without_amount(
        0,
        &keypair.1.serialize(),
        &keypair.1.serialize(),
        &metadata_type_script.calc_script_hash(),
        output_delegate_info_deltas,
    );

    let mut new_claim_tree = CLAIM_SMT::default();
    // only claim the reward of epoch 0, current epoch is 3
    new_claim_tree
        .update(addr_to_h256(&staker_addr), EpochValue(1))
        .expect("update");
    let new_claim_proof = new_claim_tree
        .merkle_proof(vec![addr_to_h256(&staker_addr)])
        .unwrap();
    let new_claim_proof = new_claim_proof
        .compile(vec![addr_to_h256(&staker_addr)])
        .unwrap()
        .0;
    let new_not_claim_info = NotClaimInfo::new_builder()
        .epoch(axon_u64(1))
        .proof(axon_bytes(&new_claim_proof))
        .build();

    let output_reward_smt_data = axon_reward_smt_data(
        metadata_type_script
            .calc_script_hash()
            .as_slice()
            .try_into()
            .unwrap(),
        new_claim_tree.root().as_slice().try_into().unwrap(),
    );
    let outputs_data = vec![
        output_reward_smt_data.as_bytes(),
        Bytes::from(axon_delegate_at_cell_data(1000, output_delegate_at_data)),
    ];

    let delegate_infos = RewardDelegateInfos::new_builder().build();
    let reward_stake_info = RewardStakeInfo::new_builder()
        .validator(axon_identity(&keypair.1.serialize()))
        .staker_amount(axon_u128(stake_amount))
        .propose_count(axon_u64(propose_count))
        .delegate_infos(delegate_infos)
        .delegate_epoch_proof(axon_bytes(&delegate_epoch_proof.0.to_vec()))
        .build();
    let reward_stake_infos = RewardStakeInfos::new_builder()
        .push(reward_stake_info)
        .build();

    let mut stake_smt_bottom_tree = BOTTOM_SMT::default();
    stake_smt_bottom_tree
        .update(addr_to_h256(&staker_addr), BottomValue(stake_amount))
        .expect("update stake smt tree");
    let stake_smt_bottom_proof = stake_smt_bottom_tree
        .merkle_proof(vec![addr_to_h256(&staker_addr)])
        .unwrap();
    let stake_smt_bottom_proof = stake_smt_bottom_proof
        .compile(vec![addr_to_h256(&staker_addr)])
        .unwrap()
        .0;

    let mut stake_smt_top_tree = TOP_SMT::default();
    let stake_smt_bottom_tree_root = stake_smt_bottom_tree.root();
    stake_smt_top_tree
        .update(u64_to_h256(claim_epoch), *stake_smt_bottom_tree_root)
        .expect("update stake smt top tree");
    let stake_smt_top_proof = stake_smt_top_tree
        .merkle_proof(vec![u64_to_h256(claim_epoch)])
        .unwrap();
    let stake_smt_top_proof = stake_smt_top_proof
        .compile(vec![u64_to_h256(claim_epoch)])
        .unwrap()
        .0;

    {
        let stake_smt_top_proof = CompiledMerkleProof(stake_smt_top_proof.clone());
        let leaves = vec![(u64_to_h256(claim_epoch), *stake_smt_bottom_tree_root)];
        let result = stake_smt_top_proof
            .verify::<Blake2bHasher>(stake_smt_top_tree.root(), leaves)
            .unwrap();
        println!("stake_smt_top_proof result: {}", result);
    }
    // println!(
    //     "stake_smt_top_proof: {:?}, root: {:?}, bottom root: {:?}, current epoch: {}",
    //     stake_smt_top_proof.clone(),
    //     stake_smt_top_tree.root(),
    //     stake_smt_bottom_tree_root,
    //     claim_epoch
    // );
    let epoch_reward_stake_info = EpochRewardStakeInfo::new_builder()
        .amount_epoch_proof(axon_bytes(&stake_smt_top_proof))
        .amount_proof(axon_bytes(&stake_smt_bottom_proof))
        .amount_root(axon_bytes(&stake_smt_bottom_tree_root.as_slice().to_vec()))
        .count_epoch_proof(axon_bytes(&propose_count_smt_top_proof))
        .count_proof(axon_bytes(&propose_count_smt_bottom_proof))
        .count_root(axon_bytes(
            &propose_count_smt_bottom_tree_root.as_slice().to_vec(),
        ))
        .reward_stake_infos(reward_stake_infos)
        .build();
    let epoch_reward_stake_infos = EpochRewardStakeInfos::new_builder()
        .push(epoch_reward_stake_info)
        .build();
    let reward_witness = RewardWitness::new_builder()
        .miner(axon_identity(&keypair.1.serialize()))
        .old_not_claim_info(old_not_claim_info)
        .reward_infos(epoch_reward_stake_infos)
        .new_not_claim_info(new_not_claim_info)
        .build();
    let reward_witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(reward_witness.as_bytes())).pack())
        .build();

    // prepare signed tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witnesses(vec![
            reward_witness.as_bytes().pack(),
            reward_witness.as_bytes().pack(),
        ])
        .cell_dep(contract_dep)
        .cell_dep(checkpoint_script_dep)
        .cell_dep(metadata_script_dep)
        .cell_dep(stake_smt_script_dep)
        .cell_dep(delegate_smt_script_dep)
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
fn test_smt_not_exist() {
    // let old_epoch = 5;
    // let new_epoch = 10;

    // for epoch in old_epoch + 1 ..= new_epoch {
    //     println!("Epoch: {}", epoch);
    // }

    let lock_info1 = LockInfo {
        addr: [0u8; 20],
        amount: 100,
    };
    let lock_infos = BTreeSet::from([lock_info1]);

    let mut tree = BOTTOM_SMT::default();
    // travese lock_infos and insert into smt
    for lock_info in lock_infos.iter() {
        let key: H256 = addr_to_h256(&lock_info.addr);
        let value = BottomValue(lock_info.amount);
        tree.update(key, value).expect("update");
    }

    let root = tree.root();
    {
        let proof = tree.merkle_proof(vec![addr_to_h256(&[0u8; 20])]).unwrap();
        let proof = proof.compile(vec![addr_to_h256(&[0u8; 20])]).unwrap().0;
        let leaves = vec![(addr_to_h256(&[0u8; 20]), u128_to_h256(100))];
        let proof = CompiledMerkleProof(proof);
        let result = proof.verify::<Blake2bHasher>(root, leaves).unwrap();
        println!("result: {}", result);
    }

    {
        // non-exist proof
        let proof = tree.merkle_proof(vec![addr_to_h256(&[1u8; 20])]).unwrap();
        let leaves = vec![(addr_to_h256(&[1u8; 20]), H256::default())];
        let proof = proof.compile(vec![addr_to_h256(&[3u8; 20])]).unwrap().0;
        // let hash_0 = u128_to_h256(0);
        // println!("hash_0: {:?},default: {:?}", hash_0, H256::default());
        let proof = CompiledMerkleProof(proof);
        let result = proof.verify::<Blake2bHasher>(root, leaves).unwrap();
        println!("result: {}", result);
    }

    {
        // non-exist proof
        let proof = tree.merkle_proof(vec![addr_to_h256(&[1u8; 20])]).unwrap();
        let leaves = vec![(addr_to_h256(&[0u8; 20]), H256::default())];
        let proof = proof.compile(vec![addr_to_h256(&[3u8; 20])]).unwrap().0;
        // let hash_0 = u128_to_h256(0);
        // println!("hash_0: {:?},default: {:?}", hash_0, H256::default());
        let proof = CompiledMerkleProof(proof);
        let result = proof.verify::<Blake2bHasher>(root, leaves).unwrap();
        println!("result: {}", result);
    }
}
