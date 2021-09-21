// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, committee::Committee, error::FastPayError, messages::*};
use std::collections::{BTreeMap, HashSet};

#[cfg(test)]
#[path = "unit_tests/authority_tests.rs"]
mod authority_tests;

/// State of an (offchain) FastPay account.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AccountState {
    /// Owner of the account. An account without owner cannot execute operations.
    pub owner: Option<AccountOwner>,
    /// Balance of the FastPay account.
    pub balance: Balance,
    /// Sequence number tracking requests.
    pub next_sequence_number: SequenceNumber,
    /// Whether we have signed a request for this sequence number already.
    pub pending: Option<Vote>,
    /// All confirmed certificates for this sender.
    pub confirmed_log: Vec<Certificate>,
    /// All confirmed certificates as a receiver.
    pub received_log: Vec<Certificate>,
    /// All executed Primary synchronization orders for this recipient.
    pub synchronization_log: Vec<PrimarySynchronizationOrder>,
}

pub struct AuthorityState {
    /// The name of this autority.
    pub name: AuthorityName,
    /// Committee of this FastPay instance.
    pub committee: Committee,
    /// The signature key pair of the authority.
    pub key_pair: KeyPair,
    /// Offchain states of FastPay accounts.
    pub accounts: BTreeMap<AccountId, AccountState>,
    /// The latest transaction index of the blockchain that the authority has seen.
    pub last_transaction_index: VersionNumber,
    /// The sharding ID of this authority shard. 0 if one shard.
    pub shard_id: ShardId,
    /// The number of shards. 1 if single shard.
    pub number_of_shards: u32,
}

/// Next step of the confirmation of an operation.
pub enum CrossShardContinuation {
    Done,
    Request {
        shard_id: ShardId,
        request: Box<CrossShardRequest>,
    },
}

/// Interface provided by each (shard of an) authority.
/// All commands return either the current account info or an error.
/// Repeating commands produces no changes and returns no error.
pub trait Authority {
    /// Initiate a new request to a FastPay or Primary account.
    fn handle_request_order(
        &mut self,
        order: RequestOrder,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// Initiate the creation of coin objects. This may trigger a number of cross-shard
    /// requests.
    fn handle_coin_creation_order(
        &mut self,
        order: CoinCreationOrder,
    ) -> Result<(Vec<Vote>, Vec<CrossShardContinuation>), FastPayError>;

    /// Confirm a request to a FastPay or Primary account.
    fn handle_confirmation_order(
        &mut self,
        order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError>;

    /// Force synchronization to finalize requests from Primary to FastPay.
    fn handle_primary_synchronization_order(
        &mut self,
        order: PrimarySynchronizationOrder,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// Handle information queries for this account.
    fn handle_account_info_query(
        &self,
        query: AccountInfoQuery,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// Handle (trusted!) cross shard request.
    fn handle_cross_shard_request(
        &mut self,
        request: CrossShardRequest,
    ) -> Result<(), FastPayError>;
}

impl AuthorityState {
    /// (Trusted) Try to update the recipient account in a confirmation order.
    /// Returns the next action to execute.
    fn update_recipient_account(&mut self, certificate: Certificate) -> Result<(), FastPayError> {
        let request = certificate
            .value
            .confirm_request()
            .ok_or(FastPayError::InvalidCrossShardRequest)?;
        // Execute the recipient's side of the operation.
        match &request.operation {
            Operation::Transfer {
                recipient: Address::FastPay(recipient),
                amount,
                ..
            }
            | Operation::SpendAndTransfer {
                recipient: Address::FastPay(recipient),
                amount,
                ..
            } => {
                fp_ensure!(self.in_shard(recipient), FastPayError::WrongShard);
                let account = self.accounts.entry(recipient.clone()).or_default();
                account.balance = account
                    .balance
                    .try_add((*amount).into())
                    .unwrap_or_else(|_| Balance::max());
                account.received_log.push(certificate.clone());
            }
            Operation::OpenAccount { new_id, new_owner } => {
                fp_ensure!(self.in_shard(new_id), FastPayError::WrongShard);
                let account = self.accounts.entry(new_id.clone()).or_default();
                assert!(account.owner.is_none()); // guaranteed under BFT assumptions.
                account.owner = Some(*new_owner);
                account.received_log.push(certificate.clone());
            }
            Operation::CloseAccount
            | Operation::Transfer {
                recipient: Address::Primary(_),
                ..
            }
            | Operation::SpendAndTransfer {
                recipient: Address::Primary(_),
                ..
            }
            | Operation::Spend { .. }
            | Operation::ChangeOwner { .. } => fp_bail!(FastPayError::InvalidCrossShardRequest),
        }
        // This concludes the confirmation of `certificate`.
        Ok(())
    }
}

impl Authority for AuthorityState {
    /// Initiate a new request.
    fn handle_request_order(
        &mut self,
        order: RequestOrder,
    ) -> Result<AccountInfoResponse, FastPayError> {
        fp_ensure!(
            self.in_shard(&order.value.request.account_id),
            FastPayError::WrongShard
        );
        // Verify that is the order was meant for this authority.
        if let Some(authority) = &order.value.limited_to {
            fp_ensure!(self.name == *authority, FastPayError::InvalidRequestOrder);
        }
        let account_id = order.value.request.account_id.clone();
        match self.accounts.get_mut(&account_id) {
            None => fp_bail!(FastPayError::UnknownSenderAccount(account_id)),
            Some(account) => {
                // Check authentication of the request.
                order.check(&account.owner)?;
                let request = order.value.request;
                fp_ensure!(
                    request.sequence_number <= SequenceNumber::max(),
                    FastPayError::InvalidSequenceNumber
                );
                if let Some(pending) = &account.pending {
                    fp_ensure!(
                        matches!(&pending.value, Value::Confirm(r) if r == &request),
                        FastPayError::PreviousRequestMustBeConfirmedFirst {
                            pending: pending.value.clone()
                        }
                    );
                    // This exact request was already signed. Return the previous value.
                    return Ok(account.make_account_info(account_id));
                }
                fp_ensure!(
                    account.next_sequence_number == request.sequence_number,
                    FastPayError::UnexpectedSequenceNumber
                );
                // Verify that the request is "safe", and return the value of the vote.
                let value = match &request.operation {
                    Operation::Transfer { amount, .. } => {
                        fp_ensure!(
                            *amount > Amount::zero(),
                            FastPayError::IncorrectTransferAmount
                        );
                        fp_ensure!(
                            account.balance >= (*amount).into(),
                            FastPayError::InsufficientFunding {
                                current_balance: account.balance
                            }
                        );
                        Value::Confirm(request)
                    }
                    Operation::Spend {
                        account_balance, ..
                    } => {
                        fp_ensure!(
                            account.balance >= (*account_balance).into(),
                            FastPayError::InsufficientFunding {
                                current_balance: account.balance
                            }
                        );
                        Value::Lock(request)
                    }
                    Operation::SpendAndTransfer { amount, .. } => {
                        let mut amount = *amount;
                        // Verify source coins.
                        for coin in order.assets {
                            coin.check(&self.committee)?;
                            match &coin.value {
                                Value::Coin(coin) if coin.account_id == account_id => {
                                    amount = amount.try_sub(coin.amount)?;
                                }
                                _ => fp_bail!(FastPayError::InvalidCoin),
                            }
                        }
                        // Verify balance.
                        fp_ensure!(
                            account.balance >= amount.into(),
                            FastPayError::InsufficientFunding {
                                current_balance: account.balance
                            }
                        );
                        Value::Confirm(request)
                    }
                    Operation::OpenAccount { new_id, .. } => {
                        let expected_id = account_id.make_child(request.sequence_number);
                        fp_ensure!(
                            new_id == &expected_id,
                            FastPayError::InvalidNewAccountId(new_id.clone())
                        );
                        Value::Confirm(request)
                    }
                    Operation::CloseAccount | Operation::ChangeOwner { .. } => {
                        // Nothing to check.
                        Value::Confirm(request)
                    }
                };
                let vote = Vote::new(value, &self.key_pair);
                account.pending = Some(vote);
                Ok(account.make_account_info(account_id))
            }
        }
    }

    /// Initiate the creation of coin objects.
    fn handle_coin_creation_order(
        &mut self,
        order: CoinCreationOrder,
    ) -> Result<(Vec<Vote>, Vec<CrossShardContinuation>), FastPayError> {
        // TODO: sharding?
        let locks = order.locks;
        let contract = order.contract;
        let hash = HashValue::new(&contract);

        let sources = contract.sources;
        let targets = contract.targets;
        fp_ensure!(
            locks.len() == sources.len(),
            FastPayError::InvalidCoinCreationOrder
        );

        let mut source_accounts = HashSet::new();
        let mut source_amount = Amount::default();
        for (i, lock) in locks.iter().enumerate() {
            let source = &sources[i];
            // Enforce uniqueness of source accounts.
            fp_ensure!(
                !source_accounts.contains(&source.account_id),
                FastPayError::InvalidCoinCreationOrder
            );
            source_accounts.insert(source.account_id.clone());
            // Verify locking certificate.
            lock.check(&self.committee)?;
            match &lock.value {
                Value::Lock(Request {
                    account_id,
                    operation:
                        Operation::Spend {
                            account_balance,
                            contract_hash,
                        },
                    ..
                }) => {
                    // Verify locked account.
                    fp_ensure!(
                        account_id == &source.account_id
                            && account_balance == &source.account_balance
                            && contract_hash == &hash,
                        FastPayError::InvalidCoinCreationOrder
                    );
                    // Update source amount.
                    source_amount = source_amount.try_add(*account_balance)?;
                }
                _ => fp_bail!(FastPayError::InvalidCoinCreationOrder),
            }
            // Verify source coins.
            for coin in &source.coins {
                // Verify coin certificate.
                coin.check(&self.committee)?;
                match &coin.value {
                    Value::Coin(Coin { account_id, amount }) => {
                        // Verify locked account.
                        fp_ensure!(account_id == &source.account_id, FastPayError::InvalidCoin);
                        // Update source amount.
                        source_amount = source_amount.try_add(*amount)?;
                    }
                    _ => fp_bail!(FastPayError::InvalidCoin),
                }
            }
        }
        // Verify target amount.
        let mut target_amount = Amount::default();
        for coin in &targets {
            target_amount = target_amount.try_add(coin.amount)?;
        }
        fp_ensure!(
            target_amount <= source_amount,
            FastPayError::InvalidCoinCreationOrder
        );
        // Construct votes and continuations.
        let mut votes = Vec::new();
        let mut continuations = Vec::new();
        for coin in targets {
            let account_id = coin.account_id.clone();
            // Create vote.
            let value = Value::Coin(coin);
            let vote = Vote::new(value, &self.key_pair);
            votes.push(vote);
            // Send cross shard request to delete source accounts (if needed).
            let shard_id = self.which_shard(&account_id);
            let cont = CrossShardContinuation::Request {
                shard_id,
                request: Box::new(CrossShardRequest::DestroyAccount { account_id }),
            };
            continuations.push(cont);
        }
        Ok((votes, continuations))
    }

    /// Confirm a request.
    fn handle_confirmation_order(
        &mut self,
        confirmation_order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError> {
        let certificate = confirmation_order.certificate;
        // Verify that the certified value is a confirmation.
        let request = certificate
            .value
            .confirm_request()
            .ok_or(FastPayError::InvalidConfirmationOrder)?;
        // Check the certificate and retrieve the request data.
        fp_ensure!(self.in_shard(&request.account_id), FastPayError::WrongShard);
        certificate.check(&self.committee)?;
        let sender = request.account_id.clone();

        let mut sender_account = self
            .accounts
            .get_mut(&sender)
            .ok_or_else(|| FastPayError::UnknownSenderAccount(sender.clone()))?;
        fp_ensure!(
            sender_account.owner.is_some(),
            FastPayError::AccountIsNotReady
        );
        if sender_account.next_sequence_number < request.sequence_number {
            fp_bail!(FastPayError::MissingEarlierConfirmations {
                current_sequence_number: sender_account.next_sequence_number
            });
        }
        if sender_account.next_sequence_number > request.sequence_number {
            // Request was already confirmed.
            let info = sender_account.make_account_info(sender.clone());
            return Ok((info, CrossShardContinuation::Done));
        }

        // Advance to next sequence number.
        sender_account.next_sequence_number = sender_account.next_sequence_number.increment()?;
        sender_account.pending = None;
        sender_account.confirmed_log.push(certificate.clone());

        // Execute the sender's side of the operation.
        let info = match &request.operation {
            Operation::OpenAccount { .. } => sender_account.make_account_info(sender.clone()),
            Operation::ChangeOwner { new_owner } => {
                sender_account.owner = Some(*new_owner);
                sender_account.make_account_info(sender.clone())
            }
            Operation::CloseAccount
            | Operation::Spend { .. }
            | Operation::SpendAndTransfer { .. } => {
                let mut info = sender_account.make_account_info(sender.clone());
                self.accounts.remove(&sender);
                info.owner = None; // Signal that the account was deleted.
                info
            }
            Operation::Transfer { amount, .. } => {
                sender_account.balance = sender_account.balance.try_sub((*amount).into())?;
                sender_account.make_account_info(sender.clone())
            }
        };

        if let Some(recipient) = request.operation.recipient() {
            // Update recipient.
            if self.in_shard(recipient) {
                // Execute the operation locally.
                self.update_recipient_account(certificate)?;
            } else {
                // Initiate a cross-shard request.
                let shard_id = self.which_shard(recipient);
                let cont = CrossShardContinuation::Request {
                    shard_id,
                    request: Box::new(CrossShardRequest::UpdateRecipient { certificate }),
                };
                return Ok((info, cont));
            }
        }
        Ok((info, CrossShardContinuation::Done))
    }

    /// Handle (trusted!) cross shard request.
    fn handle_cross_shard_request(
        &mut self,
        request: CrossShardRequest,
    ) -> Result<(), FastPayError> {
        match request {
            CrossShardRequest::UpdateRecipient { certificate } => {
                self.update_recipient_account(certificate)
            }
            CrossShardRequest::DestroyAccount { account_id } => {
                fp_ensure!(self.in_shard(&account_id), FastPayError::WrongShard);
                self.accounts.remove(&account_id);
                Ok(())
            }
        }
    }

    /// Finalize a request from Primary.
    fn handle_primary_synchronization_order(
        &mut self,
        order: PrimarySynchronizationOrder,
    ) -> Result<AccountInfoResponse, FastPayError> {
        // Update recipient state; note that the blockchain client is trusted.
        let recipient = order.recipient.clone();
        fp_ensure!(self.in_shard(&recipient), FastPayError::WrongShard);

        let recipient_account = self.accounts.entry(recipient.clone()).or_default();
        if order.transaction_index <= self.last_transaction_index {
            // Ignore old transaction index.
            return Ok(recipient_account.make_account_info(recipient));
        }
        fp_ensure!(
            order.transaction_index == self.last_transaction_index.increment()?,
            FastPayError::UnexpectedTransactionIndex
        );
        let recipient_balance = recipient_account.balance.try_add(order.amount.into())?;
        let last_transaction_index = self.last_transaction_index.increment()?;
        recipient_account.balance = recipient_balance;
        recipient_account.synchronization_log.push(order);
        self.last_transaction_index = last_transaction_index;
        Ok(recipient_account.make_account_info(recipient))
    }

    fn handle_account_info_query(
        &self,
        query: AccountInfoQuery,
    ) -> Result<AccountInfoResponse, FastPayError> {
        fp_ensure!(self.in_shard(&query.account_id), FastPayError::WrongShard);
        let account = self.account_state(&query.account_id)?;
        let mut response = account.make_account_info(query.account_id);
        if let Some(seq) = query.query_sequence_number {
            if let Some(cert) = account.confirmed_log.get(usize::from(seq)) {
                response.queried_certificate = Some(cert.clone());
            } else {
                fp_bail!(FastPayError::CertificateNotfound)
            }
        }
        if let Some(idx) = query.query_received_requests_excluding_first_nth {
            response.queried_received_requests = account.received_log[idx..].to_vec();
        }
        Ok(response)
    }
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            owner: None,
            balance: Balance::zero(),
            next_sequence_number: SequenceNumber::new(),
            pending: None,
            confirmed_log: Vec::new(),
            synchronization_log: Vec::new(),
            received_log: Vec::new(),
        }
    }
}

impl AccountState {
    fn make_account_info(&self, account_id: AccountId) -> AccountInfoResponse {
        AccountInfoResponse {
            account_id,
            owner: self.owner,
            balance: self.balance,
            next_sequence_number: self.next_sequence_number,
            pending: self.pending.clone(),
            queried_certificate: None,
            queried_received_requests: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new_with_balance(
        owner: AccountOwner,
        balance: Balance,
        received_log: Vec<Certificate>,
    ) -> Self {
        Self {
            owner: Some(owner),
            balance,
            next_sequence_number: SequenceNumber::new(),
            pending: None,
            confirmed_log: Vec::new(),
            synchronization_log: Vec::new(),
            received_log,
        }
    }
}

impl AuthorityState {
    pub fn new(committee: Committee, name: AuthorityName, key_pair: KeyPair) -> Self {
        AuthorityState {
            committee,
            name,
            key_pair,
            accounts: BTreeMap::new(),
            last_transaction_index: VersionNumber::new(),
            shard_id: 0,
            number_of_shards: 1,
        }
    }

    pub fn new_shard(
        committee: Committee,
        key_pair: KeyPair,
        shard_id: u32,
        number_of_shards: u32,
    ) -> Self {
        AuthorityState {
            committee,
            name: key_pair.public(),
            key_pair,
            accounts: BTreeMap::new(),
            last_transaction_index: VersionNumber::new(),
            shard_id,
            number_of_shards,
        }
    }

    pub fn in_shard(&self, account_id: &AccountId) -> bool {
        self.which_shard(account_id) == self.shard_id
    }

    pub fn get_shard(num_shards: u32, account_id: &AccountId) -> u32 {
        use std::hash::{Hash, Hasher};
        let mut s = std::collections::hash_map::DefaultHasher::new();
        account_id.hash(&mut s);
        (s.finish() % num_shards as u64) as u32
    }

    pub fn which_shard(&self, account_id: &AccountId) -> u32 {
        Self::get_shard(self.number_of_shards, account_id)
    }

    fn account_state(&self, account_id: &AccountId) -> Result<&AccountState, FastPayError> {
        self.accounts
            .get(account_id)
            .ok_or_else(|| FastPayError::UnknownSenderAccount(account_id.clone()))
    }

    #[cfg(test)]
    pub fn accounts_mut(&mut self) -> &mut BTreeMap<AccountId, AccountState> {
        &mut self.accounts
    }
}
