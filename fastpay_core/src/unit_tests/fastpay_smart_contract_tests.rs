// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// handle_funding_transaction
#[test]
fn test_handle_funding_transaction_zero_amount() {
    let (mut contract_state, _secret) = init_contract();
    let mut funding_transaction = init_funding_transaction();
    funding_transaction.primary_coins = Amount::zero();

    assert!(contract_state
        .handle_funding_transaction(funding_transaction)
        .is_err());
    assert_eq!(contract_state.total_balance, Amount::zero());
    assert_eq!(contract_state.last_transaction_index, SequenceNumber::new());
    assert!(contract_state.blockchain.is_empty());
    assert!(contract_state.accounts.is_empty());
}

#[test]
fn test_handle_funding_transaction_ok() {
    let (mut contract_state, _secret) = init_contract();
    let funding_transaction = init_funding_transaction();

    assert!(contract_state
        .handle_funding_transaction(funding_transaction.clone())
        .is_ok());
    assert_eq!(
        contract_state.total_balance,
        funding_transaction.primary_coins
    );
    let mut updated_last_transaction_index = SequenceNumber::new();
    updated_last_transaction_index.try_add_assign_one().unwrap();
    assert_eq!(
        contract_state.last_transaction_index,
        updated_last_transaction_index
    );
    assert_eq!(contract_state.blockchain.len(), 1);
    assert_eq!(contract_state.blockchain[0], funding_transaction);
    assert!(contract_state.accounts.is_empty());
}

// handle_redeem_transaction

#[test]
fn test_handle_redeem_transaction_ok() {
    let (mut contract_state, secret) = init_contract();
    let redeem_transaction = init_redeem_transaction(contract_state.committee.clone(), secret);
    let funding_transaction = init_funding_transaction();
    assert!(contract_state
        .handle_funding_transaction(funding_transaction)
        .is_ok());
    let mut old_total_balance = contract_state.total_balance;

    assert!(contract_state
        .handle_redeem_transaction(redeem_transaction.clone())
        .is_ok());
    let account_id = redeem_transaction
        .certificate
        .value
        .confirm_request()
        .unwrap()
        .account_id
        .clone();
    let amount = redeem_transaction
        .certificate
        .value
        .confirm_request()
        .unwrap()
        .amount()
        .unwrap();
    let account = contract_state.accounts.get(&account_id).unwrap();
    let sequence_number = redeem_transaction
        .certificate
        .value
        .confirm_request()
        .unwrap()
        .sequence_number;
    assert_eq!(account.last_redeemed, Some(sequence_number));
    old_total_balance.try_sub_assign(amount).unwrap();
    assert_eq!(contract_state.total_balance, old_total_balance);
}

#[test]
fn test_handle_redeem_transaction_negative_balance() {
    let (mut contract_state, secret) = init_contract();
    let mut redeem_transaction = init_redeem_transaction(contract_state.committee.clone(), secret);
    let funding_transaction = init_funding_transaction();
    let too_much_money = Amount::from(1000);
    assert!(contract_state
        .handle_funding_transaction(funding_transaction)
        .is_ok());
    let old_balance = contract_state.total_balance;

    let amount = redeem_transaction
        .certificate
        .value
        .confirm_request_mut()
        .unwrap()
        .amount_mut()
        .unwrap();
    amount.try_add_assign(too_much_money).unwrap();
    assert!(contract_state
        .handle_redeem_transaction(redeem_transaction)
        .is_err());
    assert_eq!(old_balance, contract_state.total_balance);
    assert!(contract_state.accounts.is_empty());
}

#[test]
fn test_handle_redeem_transaction_double_spend() {
    let (mut contract_state, secret) = init_contract();
    let redeem_transaction = init_redeem_transaction(contract_state.committee.clone(), secret);
    let funding_transaction = init_funding_transaction();
    assert!(contract_state
        .handle_funding_transaction(funding_transaction)
        .is_ok());
    assert!(contract_state
        .handle_redeem_transaction(redeem_transaction.clone())
        .is_ok());
    let old_balance = contract_state.total_balance;

    assert!(contract_state
        .handle_redeem_transaction(redeem_transaction)
        .is_err());
    assert_eq!(old_balance, contract_state.total_balance);
}

// helpers
#[cfg(test)]
fn init_contract() -> (FastPaySmartContractState, KeyPair) {
    let key_pair = KeyPair::generate();
    let name = key_pair.public();
    let mut authorities = BTreeMap::new();
    authorities.insert(name, /* voting right */ 1);
    let committee = Committee::new(authorities, None);
    (FastPaySmartContractState::new(committee), key_pair)
}

fn init_funding_transaction() -> FundingTransaction {
    FundingTransaction {
        recipient: dbg_account(1),
        primary_coins: Amount::from(5),
    }
}

#[cfg(test)]
fn init_redeem_transaction(committee: Committee, secret: KeyPair) -> RedeemTransaction {
    let request = Request {
        account_id: dbg_account(1),
        operation: Operation::Transfer {
            recipient: Address::Primary(dbg_addr(2)),
            amount: Amount::from(3),
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    let value = Value::Confirm(request);
    let vote = Vote::new(value.clone(), &secret);
    let mut builder = SignatureAggregator::new(value, &committee);
    let certificate = builder
        .append(vote.authority, vote.signature)
        .unwrap()
        .unwrap();
    RedeemTransaction { certificate }
}
