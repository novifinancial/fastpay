// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_handle_transfer_order_bad_signature() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));
    let (_, unknown_key) = get_key_pair();
    let mut bad_signature_transfer_order = transfer_order.clone();
    bad_signature_transfer_order.signature = Signature::new(&transfer_order.transfer, &unknown_key);
    assert!(authority_state
        .handle_transfer_order(bad_signature_transfer_order)
        .is_err());
    assert!(authority_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .is_none());
}

#[test]
fn test_handle_transfer_order_zero_amount() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));

    // test transfer non-positive amount
    let mut zero_amount_transfer = transfer_order.transfer;
    zero_amount_transfer.amount = Amount::zero();
    let zero_amount_transfer_order = TransferOrder::new(zero_amount_transfer, &sender_key);
    assert!(authority_state
        .handle_transfer_order(zero_amount_transfer_order)
        .is_err());
    assert!(authority_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .is_none());
}

#[test]
fn test_handle_transfer_order_unknown_sender() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));
    let (_, unknown_key) = get_key_pair();

    let unknown_sender_transfer_order = TransferOrder::new(transfer_order.transfer, &unknown_key);
    assert!(authority_state
        .handle_transfer_order(unknown_sender_transfer_order)
        .is_err());
    assert!(authority_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .is_none());
}

#[test]
fn test_handle_transfer_order_bad_sequence_number() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));

    let mut sequence_number_state = authority_state;
    let sequence_number_state_sender_account = sequence_number_state
        .accounts
        .get_mut(&dbg_account(1))
        .unwrap();
    sequence_number_state_sender_account.next_sequence_number =
        sequence_number_state_sender_account
            .next_sequence_number
            .increment()
            .unwrap();
    assert!(sequence_number_state
        .handle_transfer_order(transfer_order)
        .is_err());
    assert!(sequence_number_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .is_none());
}

#[test]
fn test_handle_transfer_order_exceed_balance() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(1000));
    assert!(authority_state
        .handle_transfer_order(transfer_order)
        .is_err());
    assert!(authority_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .is_none());
}

#[test]
fn test_handle_transfer_order_ok() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));

    let account_info = authority_state
        .handle_transfer_order(transfer_order)
        .unwrap();
    let pending_confirmation = authority_state
        .accounts
        .get(&dbg_account(1))
        .unwrap()
        .pending_confirmation
        .clone()
        .unwrap();
    assert_eq!(
        account_info.pending_confirmation.unwrap(),
        pending_confirmation
    );
}

#[test]
fn test_handle_transfer_order_double_spend() {
    let (sender, sender_key) = get_key_pair();
    let recipient = Address::FastPay(dbg_account(2));
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let transfer_order =
        init_transfer_order(dbg_account(1), &sender_key, recipient, Amount::from(5));

    let signed_order = authority_state
        .handle_transfer_order(transfer_order.clone())
        .unwrap();
    let double_spend_signed_order = authority_state
        .handle_transfer_order(transfer_order)
        .unwrap();
    assert_eq!(signed_order, double_spend_signed_order);
}

#[test]
fn test_handle_confirmation_order_unknown_sender() {
    let (_, sender_key) = get_key_pair();
    let mut authority_state =
        init_state_with_accounts(vec![(dbg_account(2), dbg_addr(2), Balance::from(0))]);
    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &authority_state,
    );

    assert!(authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order))
        .is_ok());
    assert!(authority_state.accounts.get(&dbg_account(2)).is_some());
}

#[test]
fn test_handle_confirmation_order_bad_sequence_number() {
    let (sender, sender_key) = get_key_pair();
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let sender_account = authority_state.accounts.get_mut(&dbg_account(1)).unwrap();
    sender_account.next_sequence_number = sender_account.next_sequence_number.increment().unwrap();
    // let old_account = sender_account;

    let old_balance;
    let old_seq_num;
    {
        let old_account = authority_state.accounts.get_mut(&dbg_account(1)).unwrap();
        old_balance = old_account.balance;
        old_seq_num = old_account.next_sequence_number;
    }

    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &authority_state,
    );
    // Replays are ignored.
    assert!(authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order))
        .is_ok());
    let new_account = authority_state.accounts.get_mut(&dbg_account(1)).unwrap();
    assert_eq!(old_balance, new_account.balance);
    assert_eq!(old_seq_num, new_account.next_sequence_number);
    assert_eq!(new_account.confirmed_log, Vec::new());
}

#[test]
fn test_handle_confirmation_order_exceed_balance() {
    let (sender, sender_key) = get_key_pair();
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);

    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(1000),
        &authority_state,
    );
    assert!(authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order))
        .is_ok());
    let new_account = authority_state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(-995), new_account.balance);
    assert_eq!(SequenceNumber::from(1), new_account.next_sequence_number);
    assert_eq!(new_account.confirmed_log.len(), 1);
    assert!(authority_state.accounts.get(&dbg_account(2)).is_some());
}

#[test]
fn test_handle_confirmation_order_receiver_balance_overflow() {
    let (sender, sender_key) = get_key_pair();
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(1)),
        (dbg_account(2), dbg_addr(2), Balance::max()),
    ]);

    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(1),
        &authority_state,
    );
    assert!(authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order))
        .is_ok());
    let new_sender_account = authority_state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(0), new_sender_account.balance);
    assert_eq!(
        SequenceNumber::from(1),
        new_sender_account.next_sequence_number
    );
    assert_eq!(new_sender_account.confirmed_log.len(), 1);
    let new_recipient_account = authority_state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(Balance::max(), new_recipient_account.balance);
}

#[test]
fn test_handle_confirmation_order_receiver_equal_sender() {
    let (name, key) = get_key_pair();
    let mut authority_state = init_state_with_account(dbg_account(1), name, Balance::from(1));

    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &key,
        Address::FastPay(dbg_account(1)),
        Amount::from(10),
        &authority_state,
    );
    assert!(authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order))
        .is_ok());
    let account = authority_state.accounts.get(&dbg_account(1)).unwrap();
    assert_eq!(Balance::from(1), account.balance);
    assert_eq!(SequenceNumber::from(1), account.next_sequence_number);
    assert_eq!(account.confirmed_log.len(), 1);
}

#[test]
fn test_handle_cross_shard_recipient_commit() {
    let (_, sender_key) = get_key_pair();
    // Sender has no account on this shard.
    let mut authority_state =
        init_state_with_accounts(vec![(dbg_account(2), dbg_addr(2), Balance::from(1))]);
    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(10),
        &authority_state,
    );
    assert!(authority_state
        .handle_cross_shard_recipient_commit(certified_transfer_order)
        .is_ok());
    let account = authority_state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(Balance::from(11), account.balance);
    assert_eq!(SequenceNumber::from(0), account.next_sequence_number);
    assert_eq!(account.confirmed_log.len(), 0);
}

#[test]
fn test_handle_confirmation_order_ok() {
    let (sender, sender_key) = get_key_pair();
    let mut authority_state = init_state_with_accounts(vec![
        (dbg_account(1), sender, Balance::from(5)),
        (dbg_account(2), dbg_addr(2), Balance::from(0)),
    ]);
    let certified_transfer_order = init_certified_transfer_order(
        dbg_account(1),
        &sender_key,
        Address::FastPay(dbg_account(2)),
        Amount::from(5),
        &authority_state,
    );

    let old_account = authority_state.accounts.get_mut(&dbg_account(1)).unwrap();
    let mut next_sequence_number = old_account.next_sequence_number;
    next_sequence_number = next_sequence_number.increment().unwrap();
    let mut remaining_balance = old_account.balance;
    remaining_balance = remaining_balance
        .try_sub(certified_transfer_order.value.transfer.amount.into())
        .unwrap();

    let (info, _) = authority_state
        .handle_confirmation_order(ConfirmationOrder::new(certified_transfer_order.clone()))
        .unwrap();
    assert_eq!(dbg_account(1), info.account_id);
    assert_eq!(remaining_balance, info.balance);
    assert_eq!(next_sequence_number, info.next_sequence_number);
    assert_eq!(None, info.pending_confirmation);
    assert_eq!(
        authority_state
            .accounts
            .get(&dbg_account(1))
            .unwrap()
            .confirmed_log,
        vec![certified_transfer_order.clone()]
    );

    let recipient_account = authority_state.accounts.get(&dbg_account(2)).unwrap();
    assert_eq!(
        recipient_account.balance,
        certified_transfer_order.value.transfer.amount.into()
    );

    let info_request = AccountInfoRequest {
        account_id: dbg_account(2),
        request_sequence_number: None,
        request_received_transfers_excluding_first_nth: Some(0),
    };
    let response = authority_state
        .handle_account_info_request(info_request)
        .unwrap();
    assert_eq!(response.requested_received_transfers.len(), 1);
    assert_eq!(
        response.requested_received_transfers[0]
            .value
            .transfer
            .amount,
        Amount::from(5)
    );
}

#[test]
fn test_handle_primary_synchronization_order_update() {
    let (owner, _) = get_key_pair();
    let account_id = dbg_account(1);
    let mut state = init_state_with_accounts(vec![(account_id.clone(), owner, Balance::from(0))]);
    let mut updated_transaction_index = state.last_transaction_index;
    let order = init_primary_synchronization_order(account_id.clone());

    assert!(state
        .handle_primary_synchronization_order(order.clone())
        .is_ok());
    updated_transaction_index = updated_transaction_index.increment().unwrap();
    assert_eq!(state.last_transaction_index, updated_transaction_index);
    let account = state.accounts.get(&account_id).unwrap();
    assert_eq!(account.balance, order.amount.into());
    assert_eq!(state.accounts.len(), 1);
}

#[test]
fn test_handle_primary_synchronization_order_double_spend() {
    let (owner, _) = get_key_pair();
    let account_id = dbg_account(1);
    let mut state = init_state_with_accounts(vec![(account_id.clone(), owner, Balance::from(0))]);
    let mut updated_transaction_index = state.last_transaction_index;
    let order = init_primary_synchronization_order(account_id.clone());

    assert!(state
        .handle_primary_synchronization_order(order.clone())
        .is_ok());
    updated_transaction_index = updated_transaction_index.increment().unwrap();
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
    let authority_state = init_state_with_account(sender.clone(), dbg_addr(1), Balance::from(5));
    assert_eq!(
        authority_state.accounts.get(&sender).unwrap(),
        authority_state.account_state(&sender).unwrap()
    );
}

#[test]
fn test_account_state_unknown_account() {
    let sender = dbg_account(1);
    let unknown_account_id = dbg_account(99);
    let authority_state = init_state_with_account(sender, dbg_addr(1), Balance::from(5));
    assert!(authority_state.account_state(&unknown_account_id).is_err());
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
    let (authority_name, authority_key) = get_key_pair();
    let mut authorities = BTreeMap::new();
    authorities.insert(authority_name, /* voting right */ 1);
    let committee = Committee::new(authorities);
    AuthorityState::new(committee, authority_name, authority_key)
}

#[cfg(test)]
fn init_state_with_accounts<I: IntoIterator<Item = (AccountId, AccountOwner, Balance)>>(
    balances: I,
) -> AuthorityState {
    let mut state = init_state();
    for (id, owner, balance) in balances {
        let account = state
            .accounts
            .entry(id)
            .or_insert_with(|| AccountOffchainState::new(owner));
        account.balance = balance;
    }
    state
}

#[cfg(test)]
fn init_state_with_account(id: AccountId, owner: AccountOwner, balance: Balance) -> AuthorityState {
    init_state_with_accounts(std::iter::once((id, owner, balance)))
}

#[cfg(test)]
fn init_transfer_order(
    account_id: AccountId,
    secret: &KeyPair,
    recipient: Address,
    amount: Amount,
) -> TransferOrder {
    let transfer = Transfer {
        account_id,
        recipient,
        amount,
        sequence_number: SequenceNumber::new(),
        user_data: UserData::default(),
    };
    TransferOrder::new(transfer, secret)
}

#[cfg(test)]
fn init_certified_transfer_order(
    account_id: AccountId,
    secret: &KeyPair,
    recipient: Address,
    amount: Amount,
    authority_state: &AuthorityState,
) -> CertifiedTransferOrder {
    let transfer_order = init_transfer_order(account_id, secret, recipient, amount);
    let vote = SignedTransferOrder::new(
        transfer_order.clone(),
        authority_state.name,
        &authority_state.secret,
    );
    let mut builder =
        SignatureAggregator::try_new(transfer_order, &authority_state.committee).unwrap();
    builder
        .append(vote.authority, vote.signature)
        .unwrap()
        .unwrap()
}

#[cfg(test)]
fn init_primary_synchronization_order(recipient: AccountId) -> PrimarySynchronizationOrder {
    let mut transaction_index = VersionNumber::new();
    transaction_index = transaction_index.increment().unwrap();
    PrimarySynchronizationOrder {
        recipient,
        amount: Amount::from(5),
        transaction_index,
    }
}
