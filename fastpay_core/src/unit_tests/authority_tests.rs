// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_handle_request_order_bad_signature() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::from(5));
    let unknown_key_pair = KeyPair::generate();
    let mut bad_signature_request_order = request_order.clone();
    bad_signature_request_order.signature = Signature::new(&request_order.value, &unknown_key_pair);
    assert!(state
        .handle_request_order(bad_signature_request_order)
        .is_err());
    assert!(state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .is_none());
}

#[test]
fn test_handle_request_order_zero_amount() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    // test request non-positive amount
    let zero_amount_request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::zero());
    assert!(state
        .handle_request_order(zero_amount_request_order)
        .is_err());
    assert!(state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .is_none());
}

#[test]
fn test_handle_request_order_unknown_sender() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::from(5));
    let unknown_key = KeyPair::generate();

    let unknown_sender_request_order =
        RequestOrder::new(request_order.value, &unknown_key, Vec::new());
    assert!(state
        .handle_request_order(unknown_sender_request_order)
        .is_err());
    assert!(state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .is_none());
}

#[test]
fn test_handle_request_order_bad_sequence_number() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::from(5));

    let mut sequence_number_state = state;
    let sequence_number_state_sender_account = sequence_number_state
        .accounts
        .get_mut(&dbg_account(1))
        .unwrap();
    sequence_number_state_sender_account
        .next_sequence_number
        .try_add_assign_one()
        .unwrap();
    assert!(sequence_number_state
        .handle_request_order(request_order)
        .is_err());
    assert!(sequence_number_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .is_none());
}

#[test]
fn test_handle_request_order_exceed_balance() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order = init_request_order(
        dbg_account(1),
        &sender_key_pair,
        recipient,
        Amount::from(1000),
    );
    assert!(state.handle_request_order(request_order).is_err());
    assert!(state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .is_none());
}

#[test]
fn test_handle_request_order_ok() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::from(5));

    let account_info = state.handle_request_order(request_order).unwrap();
    let pending = state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending
        .clone()
        .unwrap();
    assert_eq!(account_info.pending.unwrap(), pending);
}

#[test]
fn test_handle_request_order_double_spend() {
    let sender_key_pair = KeyPair::generate();
    let recipient = Address::FastPay(dbg_account(2));
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let request_order =
        init_request_order(dbg_account(1), &sender_key_pair, recipient, Amount::from(5));

    let vote = state.handle_request_order(request_order.clone()).unwrap();
    let double_spend_vote = state.handle_request_order(request_order).unwrap();
    assert_eq!(vote, double_spend_vote);
}

#[test]
fn test_handle_confirmation_order_unknown_sender() {
    let sender_key_pair = KeyPair::generate();
    let mut state = init_state_with_accounts(vec![(dbg_account(2), dbg_addr(2), Balance::from(0))]);
    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &state,
    );

    assert!(state
        .handle_confirmation_order(ConfirmationOrder::new(certificate))
        .is_err());
    assert!(state.accounts.get(&dbg_account(2)).is_some());
    assert!(state.accounts.get(&dbg_account(1)).is_none());
}

#[test]
fn test_handle_confirmation_order_bad_sequence_number() {
    let sender_key_pair = KeyPair::generate();
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let sender_account = state.accounts.get_mut(&dbg_account(1)).unwrap();
    sender_account
        .next_sequence_number
        .try_add_assign_one()
        .unwrap();
    // let old_account = sender_account;

    let old_balance;
    let old_seq_num;
    {
        let old_account = state.accounts.get_mut(&dbg_account(1)).unwrap();
        old_balance = old_account.balance;
        old_seq_num = old_account.next_sequence_number;
    }

    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &state,
    );
    // Replays are ignored.
    assert!(state
        .handle_confirmation_order(ConfirmationOrder::new(certificate))
        .is_ok());
    let new_account = state.accounts.get_mut(&dbg_account(1)).unwrap();
    assert_eq!(old_balance, new_account.balance);
    assert_eq!(old_seq_num, new_account.next_sequence_number);
    assert_eq!(new_account.confirmed_log, Vec::new());
}

#[test]
fn test_handle_confirmation_order_exceed_balance() {
    let sender_key_pair = KeyPair::generate();
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);

    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(1000),
        &state,
    );
    assert!(state
        .handle_confirmation_order(ConfirmationOrder::new(certificate))
        .is_ok());
    let new_account = state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(-995), new_account.balance);
    assert_eq!(SequenceNumber::from(1), new_account.next_sequence_number);
    assert_eq!(new_account.confirmed_log.len(), 1);
    assert!(state.accounts.get(&dbg_account(2)).is_some());
}

#[test]
fn test_handle_confirmation_order_receiver_balance_overflow() {
    let sender_key_pair = KeyPair::generate();
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(1)),
        (dbg_account(2), dbg_addr(2), Balance::max()),
    ]);

    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(1),
        &state,
    );
    assert!(state
        .handle_confirmation_order(ConfirmationOrder::new(certificate))
        .is_ok());
    let new_sender_account = state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(0), new_sender_account.balance);
    assert_eq!(
        SequenceNumber::from(1),
        new_sender_account.next_sequence_number
    );
    assert_eq!(new_sender_account.confirmed_log.len(), 1);
    let new_recipient_account = state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(Balance::max(), new_recipient_account.balance);
}

#[test]
fn test_handle_confirmation_order_receiver_equal_sender() {
    let key_pair = KeyPair::generate();
    let name = key_pair.public();
    let mut state = init_state_with_account(dbg_account(1), name, Balance::from(1));

    let certificate = init_certificate(
        dbg_account(1),
        &key_pair,
        Address::FastPay(dbg_account(1)),
        Amount::from(10),
        &state,
    );
    assert!(state
        .handle_confirmation_order(ConfirmationOrder::new(certificate))
        .is_ok());
    let account = state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(1), account.balance);
    assert_eq!(SequenceNumber::from(1), account.next_sequence_number);
    assert_eq!(account.confirmed_log.len(), 1);
}

#[test]
fn test_update_recipient_account() {
    let sender_key_pair = KeyPair::generate();
    // Sender has no account on this shard.
    let mut state = init_state_with_accounts(vec![(dbg_account(2), dbg_addr(2), Balance::from(1))]);
    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(10),
        &state,
    );
    let operation = certificate
        .value
        .confirm_request()
        .unwrap()
        .operation
        .clone();
    assert!(state
        .update_recipient_account(operation, certificate)
        .is_ok());
    let account = state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(Balance::from(11), account.balance);
    assert_eq!(SequenceNumber::from(0), account.next_sequence_number);
    assert_eq!(account.confirmed_log.len(), 0);
}

#[test]
fn test_handle_confirmation_order_ok() {
    let sender_key_pair = KeyPair::generate();
    let mut state = init_state_with_accounts(vec![
        (dbg_account(1), sender_key_pair.public(), Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let certificate = init_certificate(
        dbg_account(1),
        &sender_key_pair,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &state,
    );

    let old_account = state.accounts.get_mut(&dbg_account(1)).unwrap();
    let mut next_sequence_number = old_account.next_sequence_number;
    next_sequence_number.try_add_assign_one().unwrap();
    let mut remaining_balance = old_account.balance;
    remaining_balance
        .try_sub_assign(
            certificate
                .value
                .confirm_request()
                .unwrap()
                .amount()
                .unwrap()
                .into(),
        )
        .unwrap();

    let (info, _) = state
        .handle_confirmation_order(ConfirmationOrder::new(certificate.clone()))
        .unwrap();
    assert_eq!(dbg_account(1), info.account_id);
    assert_eq!(remaining_balance, info.balance);
    assert_eq!(next_sequence_number, info.next_sequence_number);
    assert_eq!(None, info.pending);
    assert_eq!(
        state.accounts.get(&dbg_account(1)).unwrap().confirmed_log,
        vec![certificate.clone()]
    );

    let recipient_account = state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(
        recipient_account.balance,
        certificate
            .value
            .confirm_request()
            .unwrap()
            .amount()
            .unwrap()
            .into()
    );

    let info_query = AccountInfoQuery {
        account_id: dbg_account(2),
        query_sequence_number: None,
        query_received_certificates_excluding_first_nth: Some(0),
    };
    let response = state.handle_account_info_query(info_query).unwrap();
    assert_eq!(response.queried_received_certificates.len(), 1);
    assert_eq!(
        response.queried_received_certificates[0]
            .value
            .confirm_request()
            .unwrap()
            .amount()
            .unwrap(),
        Amount::from(5)
    );
}

#[test]
fn test_handle_primary_synchronization_order_update() {
    let owner = KeyPair::generate().public();
    let account_id = dbg_account(1);
    let mut state = init_state_with_accounts(vec![(account_id.clone(), owner, Balance::from(0))]);
    let mut updated_transaction_index = state.last_transaction_index;
    let order = init_primary_synchronization_order(account_id.clone());

    assert!(state
        .handle_primary_synchronization_order(order.clone())
        .is_ok());
    updated_transaction_index.try_add_assign_one().unwrap();
    assert_eq!(state.last_transaction_index, updated_transaction_index);
    let account = state.accounts.get(&account_id).unwrap();
    assert_eq!(account.balance, order.amount.into());
    assert_eq!(state.accounts.len(), 1);
}

#[test]
fn test_handle_primary_synchronization_order_double_spend() {
    let owner = KeyPair::generate().public();
    let account_id = dbg_account(1);
    let mut state = init_state_with_accounts(vec![(account_id.clone(), owner, Balance::from(0))]);
    let mut updated_transaction_index = state.last_transaction_index;
    let order = init_primary_synchronization_order(account_id.clone());

    assert!(state
        .handle_primary_synchronization_order(order.clone())
        .is_ok());
    updated_transaction_index.try_add_assign_one().unwrap();
    // Replays are ignored.
    assert!(state
        .handle_primary_synchronization_order(order.clone())
        .is_ok());
    assert_eq!(state.last_transaction_index, updated_transaction_index);
    let account = state.accounts.get(&account_id).unwrap();
    assert_eq!(account.balance, order.amount.into());
    assert_eq!(state.accounts.len(), 1);
}

#[test]
fn test_account_state_ok() {
    let sender = dbg_account(1);
    let state = init_state_with_account(sender.clone(), dbg_addr(1), Balance::from(5));
    assert_eq!(
        state.accounts.get(&sender).unwrap(),
        state.account_state(&sender).unwrap()
    );
}

#[test]
fn test_account_state_unknown_account() {
    let sender = dbg_account(1);
    let unknown_account_id = dbg_account(99);
    let state = init_state_with_account(sender, dbg_addr(1), Balance::from(5));
    assert!(state.account_state(&unknown_account_id).is_err());
}

#[test]
fn test_get_shards() {
    let num_shards = 16u32;
    let mut found = vec![false; num_shards as usize];
    let mut left = num_shards;
    let mut i = 1;
    loop {
        let shard = AuthorityState::get_shard(num_shards, &dbg_account(i)) as usize;
        println!("found {}", shard);
        if !found[shard] {
            found[shard] = true;
            left -= 1;
            if left == 0 {
                break;
            }
        }
        i += 1;
    }
}

// helpers

#[cfg(test)]
fn init_state() -> AuthorityState {
    let key_pair = KeyPair::generate();
    let name = key_pair.public();
    let mut authorities = BTreeMap::new();
    authorities.insert(name, /* voting right */ 1);
    let committee = Committee::new(authorities);
    AuthorityState::new(committee, name, key_pair)
}

#[cfg(test)]
fn init_state_with_accounts<I: IntoIterator<Item = (AccountId, AccountOwner, Balance)>>(
    balances: I,
) -> AuthorityState {
    let mut state = init_state();
    for (id, owner, balance) in balances {
        let account = AccountState::new(owner, balance);
        state.accounts.insert(id, account);
    }
    state
}

#[cfg(test)]
fn init_state_with_account(id: AccountId, owner: AccountOwner, balance: Balance) -> AuthorityState {
    init_state_with_accounts(std::iter::once((id, owner, balance)))
}

#[cfg(test)]
fn init_request_order(
    account_id: AccountId,
    secret: &KeyPair,
    recipient: Address,
    amount: Amount,
) -> RequestOrder {
    let request = Request {
        account_id,
        operation: Operation::Transfer {
            recipient,
            amount,
            user_data: UserData::default(),
        },
        sequence_number: SequenceNumber::new(),
    };
    RequestOrder::new(request.into(), secret, Vec::new())
}

#[cfg(test)]
fn init_certificate(
    account_id: AccountId,
    key_pair: &KeyPair,
    recipient: Address,
    amount: Amount,
    state: &AuthorityState,
) -> Certificate {
    let request = init_request_order(account_id, key_pair, recipient, amount)
        .value
        .request;
    let value = Value::Confirm(request);
    let vote = Vote::new(value.clone(), &state.key_pair);
    let mut builder = SignatureAggregator::new(value, &state.committee);
    builder
        .append(vote.authority, vote.signature)
        .unwrap()
        .unwrap()
}

#[cfg(test)]
fn init_primary_synchronization_order(recipient: AccountId) -> PrimarySynchronizationOrder {
    let mut transaction_index = VersionNumber::new();
    transaction_index.try_add_assign_one().unwrap();
    PrimarySynchronizationOrder {
        recipient,
        amount: Amount::from(5),
        transaction_index,
    }
}
