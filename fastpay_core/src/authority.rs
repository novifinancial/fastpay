// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account::AccountState, base_types::*, committee::Committee, consensus::ConsensusState,
    error::FastPayError, messages::*,
};
use bls12_381::Scalar;
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[cfg(test)]
#[path = "unit_tests/authority_tests.rs"]
mod authority_tests;

/// State of an authority.
pub struct AuthorityState {
    /// The name of this authority.
    pub name: AuthorityName,
    /// Committee of this FastPay instance.
    pub committee: Committee,
    /// The signature key pair of the authority.
    pub key_pair: KeyPair,
    /// The signature key pair of the authority.
    pub coconut_key_pair: Option<coconut::KeyPair>,
    /// States of FastPay accounts.
    pub accounts: BTreeMap<AccountId, AccountState>,
    /// States of consensus instances.
    pub instances: BTreeMap<AccountId, ConsensusState>,
    /// The latest transaction index of the blockchain that the authority has seen.
    pub last_transaction_index: SequenceNumber,
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

/// The response to a consensus order.
pub enum ConsensusResponse {
    Info(ConsensusInfoResponse),
    Vote(Vote),
    Continuations(Vec<CrossShardContinuation>),
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

    /// Confirm a request to a FastPay or Primary account.
    fn handle_confirmation_order(
        &mut self,
        order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError>;

    /// Initiate the creation of coin objects. This may trigger a number of cross-shard
    /// requests.
    fn handle_coin_creation_order(
        &mut self,
        order: CoinCreationOrder,
    ) -> Result<(CoinCreationResponse, Vec<CrossShardContinuation>), FastPayError>;

    /// Process a message meant for a consensus instance.
    fn handle_consensus_order(
        &mut self,
        order: ConsensusOrder,
    ) -> Result<ConsensusResponse, FastPayError>;

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
    /// (Trusted) Process a confirmed request issued from an account.
    fn process_confirmed_request(
        &mut self,
        request: Request,
        certificate: Certificate, // For logging purpose
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError> {
        // Verify sharding. Disable this check for benchmarks.
        #[cfg(not(feature = "benchmark"))]
        fp_ensure!(self.in_shard(&request.account_id), FastPayError::WrongShard);
        // Obtain the sender's account.
        let sender = request.account_id.clone();
        let account = self
            .accounts
            .get_mut(&sender)
            .ok_or_else(|| FastPayError::InactiveAccount(sender.clone()))?;
        // Check that the account is active and ready for this confirmation.
        fp_ensure!(
            account.owner.is_some(),
            FastPayError::InactiveAccount(sender.clone())
        );
        if account.next_sequence_number < request.sequence_number {
            fp_bail!(FastPayError::MissingEarlierConfirmations {
                current_sequence_number: account.next_sequence_number
            });
        }
        if account.next_sequence_number > request.sequence_number {
            // Request was already confirmed.
            let info = account.make_account_info(sender.clone());
            return Ok((info, CrossShardContinuation::Done));
        }

        // Execute the sender's side of the operation.
        account.apply_operation_as_sender(&request.operation, certificate.clone())?;
        // Advance to next sequence number.
        account.next_sequence_number.try_add_assign_one()?;
        account.pending = None;
        // Final touch on the sender's account.
        let info = account.make_account_info(sender.clone());
        if account.owner.is_none() {
            // Tentatively remove inactive account. (It might be created again as a
            // recipient, though. To solve this, we may implement additional cleanups in
            // the future.)
            self.accounts.remove(&sender);
        }

        if let Some(recipient) = request.operation.recipient() {
            // Update recipient.
            if self.in_shard(recipient) {
                // Execute the operation locally.
                self.update_recipient_account(request.operation.clone(), certificate)?;
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

    /// (Trusted) Try to update the recipient account in a confirmed request.
    fn update_recipient_account(
        &mut self,
        operation: Operation,
        certificate: Certificate,
    ) -> Result<(), FastPayError> {
        if let Some(recipient) = operation.recipient() {
            fp_ensure!(self.in_shard(recipient), FastPayError::WrongShard);
            // Execute the recipient's side of the operation.
            let account = self.accounts.entry(recipient.clone()).or_default();
            account.apply_operation_as_recipient(&operation, certificate)?;
        } else if let Operation::StartConsensusInstance {
            new_id,
            accounts,
            functionality,
        } = &operation
        {
            fp_ensure!(self.in_shard(new_id), FastPayError::WrongShard);
            assert!(!self.instances.contains_key(new_id)); // guaranteed under BFT assumptions.
            let instance = ConsensusState::new(*functionality, accounts.clone(), certificate);
            self.instances.insert(new_id.clone(), instance);
        }
        // This concludes the confirmation of `certificate`.
        Ok(())
    }
}

impl Authority for AuthorityState {
    fn handle_request_order(
        &mut self,
        order: RequestOrder,
    ) -> Result<AccountInfoResponse, FastPayError> {
        // Verify sharding. Disable this check for benchmarks.
        #[cfg(not(feature = "benchmark"))]
        fp_ensure!(
            self.in_shard(&order.value.request.account_id),
            FastPayError::WrongShard
        );
        // Verify that the order was meant for this authority.
        if let Some(authority) = &order.value.limited_to {
            fp_ensure!(self.name == *authority, FastPayError::InvalidRequestOrder);
        }
        // Verify assets in the order.
        for asset in &order.assets {
            asset.check(&self.committee)?;
        }
        // Obtain the sender's account. If we are running a benchmark, the sender account is random and does not exist,
        // so we create it here on the spot.
        let sender = order.value.request.account_id.clone();

        #[cfg(feature = "benchmark")]
        {
            let state = AccountState::new(order.owner, Balance::from(10));
            self.accounts.insert(sender.clone(), state);
        }

        let account = self
            .accounts
            .get_mut(&sender)
            .ok_or_else(|| FastPayError::InactiveAccount(sender.clone()))?;
        fp_ensure!(
            account.owner.is_some(),
            FastPayError::InactiveAccount(sender)
        );
        // Check authentication of the request.
        order.check(&account.owner)?;
        // Check the account is ready for this new request.
        let request = order.value.request;
        fp_ensure!(
            request.sequence_number <= SequenceNumber::max(),
            FastPayError::InvalidSequenceNumber
        );
        fp_ensure!(
            account.next_sequence_number == request.sequence_number,
            FastPayError::UnexpectedSequenceNumber
        );
        if let Some(pending) = &account.pending {
            fp_ensure!(
                matches!(&pending.value, Value::Confirm(r) | Value::Lock(r) if r == &request),
                FastPayError::PreviousRequestMustBeConfirmedFirst {
                    pending: pending.value.clone()
                }
            );
            // This exact request was already signed. Return the previous vote.
            return Ok(account.make_account_info(sender));
        }
        // Verify that the request is safe, and return the value of the vote.
        let value = account.validate_operation(request, &order.assets)?;
        let vote = Vote::new(value, &self.key_pair);
        account.pending = Some(vote);
        Ok(account.make_account_info(sender))
    }

    /// Confirm a request.
    fn handle_confirmation_order(
        &mut self,
        confirmation_order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError> {
        // Verify that the certified value is a confirmation.
        let certificate = confirmation_order.certificate;

        #[cfg(feature = "benchmark")]
        {
            let account_id = certificate.value.confirm_account_id().unwrap();
            let id = account_id.sequence_number().unwrap().0;
            // NOTE: This log entry is used to compute performance.
            log::info!("Received certificate {}", id);
        }

        let request = certificate
            .value
            .confirm_request()
            .ok_or(FastPayError::InvalidConfirmationOrder)?;
        // Verify the certificate.
        certificate.check(&self.committee)?;
        // Process the request.
        self.process_confirmed_request(request.clone(), certificate)
    }

    fn handle_coin_creation_order(
        &mut self,
        order: CoinCreationOrder,
    ) -> Result<(CoinCreationResponse, Vec<CrossShardContinuation>), FastPayError> {
        // No sharding is currently enforced for coin creation orders.
        let locks = order.locks;
        let description = order.description;
        let hash = HashValue::new(&description);
        let sources = description.sources;
        let targets = description.targets;
        fp_ensure!(
            locks.len() == sources.len(),
            FastPayError::InvalidCoinCreationOrder
        );

        let mut tracking_id = AccountId::default();
        let mut source_accounts = HashSet::new();
        let mut source_amount = Amount::default();
        for (i, lock) in locks.iter().enumerate() {
            let source = &sources[i];
            tracking_id = source.account_id.clone();
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
                            description_hash,
                        },
                    ..
                }) => {
                    // Verify locked account.
                    #[cfg(not(feature = "benchmark"))]
                    fp_ensure!(
                        account_id == &source.account_id
                            && account_balance == &source.account_balance
                            && description_hash == &hash,
                        FastPayError::InvalidCoinCreationOrder
                    );
                    #[cfg(feature = "benchmark")]
                    {
                        let _account_id = account_id;
                        let _account_balance = account_balance;
                        let _description_hash = description_hash;
                        let _hash = hash;
                    }
                    // Update source amount.
                    source_amount.try_add_assign(*account_balance)?;
                }
                _ => fp_bail!(FastPayError::InvalidCoinCreationOrder),
            }
            // Verify transparent source coins.
            let mut assets = Vec::new();
            for coin in &source.transparent_coins {
                coin.check(&self.committee)?;
                assets.push(Asset::TransparentCoin {
                    certificate: coin.clone(),
                });
            }
            let coin_amount = AccountState::verify_linked_assets(&source.account_id, &assets)?;
            source_amount.try_add_assign(coin_amount)?;
        }
        // Verify target amount and/or coconut proof.
        let mut target_amount = Amount::zero();
        for coin in &targets {
            fp_ensure!(
                coin.amount > Amount::zero(),
                FastPayError::InvalidCoinCreationOrder
            );
            target_amount.try_add_assign(coin.amount)?;
        }
        let blinded_coins = match &description.coconut_request {
            None => {
                fp_ensure!(
                    target_amount <= source_amount,
                    FastPayError::InsufficientFunding {
                        current_balance: source_amount.into()
                    }
                );
                // No blinded coins.
                None
            }
            Some(request) => {
                // Verify input coins. Note: Those must be given listed in the right order
                // in the request.
                let mut keys = Vec::new();
                for source in &sources {
                    let mut seen = BTreeSet::new();
                    for public_seed in &source.opaque_coin_public_seeds {
                        // Seeds must be distinct within the same source.
                        fp_ensure!(
                            !seen.contains(public_seed),
                            FastPayError::InvalidCoinCreationOrder
                        );
                        seen.insert(*public_seed);
                        let key = CoconutKey {
                            #[cfg(not(feature = "benchmark"))]
                            account_id: source.account_id.clone(),
                            #[cfg(feature = "benchmark")]
                            account_id: AccountId::new(vec![SequenceNumber::from(10)]),
                            public_seed: *public_seed,
                        };
                        keys.push(key.scalar());
                    }
                }
                // Verify coconut proof.
                let offset =
                    Scalar::from(u64::from(source_amount)) - Scalar::from(u64::from(target_amount));
                let setup = &self
                    .committee
                    .coconut_setup
                    .as_ref()
                    .ok_or(FastPayError::InvalidCoinCreationOrder)?;
                request
                    .verify(&setup.parameters, &setup.verification_key, &keys, &offset)
                    .map_err(|_| FastPayError::InvalidCoinCreationOrder)?;
                if request.cms.is_empty() {
                    None
                } else {
                    let secret = &self
                        .coconut_key_pair
                        .as_ref()
                        .ok_or(FastPayError::InvalidCoinCreationOrder)?
                        .secret;
                    // Build blinded shares for opaque coins.
                    let coins = coconut::BlindedCoins::new(
                        &setup.parameters,
                        secret,
                        &request.cms,
                        &request.cs,
                    );
                    Some(coins)
                }
            }
        };
        // Construct votes for transparent coins
        let mut votes = Vec::new();
        for coin in targets {
            // Create vote.
            let value = Value::Coin(coin);
            let vote = Vote::new(value, &self.key_pair);
            votes.push(vote);
        }
        // Build cross-shard requests to delete source accounts.
        let mut continuations = Vec::new();
        for account_id in source_accounts {
            // Send cross shard request to delete source account (if needed). This is a
            // best effort to quickly save storage.
            let shard_id = self.which_shard(&account_id);
            let cont = CrossShardContinuation::Request {
                shard_id,
                request: Box::new(CrossShardRequest::DestroyAccount { account_id }),
            };
            continuations.push(cont);
        }
        let response = CoinCreationResponse {
            votes,
            blinded_coins,
            tracking_id,
        };
        Ok((response, continuations))
    }

    /// Process a message meant for a consensus instance.
    fn handle_consensus_order(
        &mut self,
        order: ConsensusOrder,
    ) -> Result<ConsensusResponse, FastPayError> {
        match order {
            ConsensusOrder::GetStatus { instance_id } => {
                let instance = self
                    .instances
                    .get_mut(&instance_id)
                    .ok_or(FastPayError::UnknownConsensusInstance(instance_id))?;
                let info = ConsensusInfoResponse {
                    locked_accounts: instance.locked_accounts.clone(),
                    proposed: instance.proposed.clone(),
                    locked: instance.locked.clone(),
                    received: instance.received.clone(),
                };
                Ok(ConsensusResponse::Info(info))
            }
            ConsensusOrder::Propose {
                proposal,
                owner,
                signature,
                locks,
            } => {
                let instance = self
                    .instances
                    .get_mut(&proposal.instance_id)
                    .ok_or_else(|| {
                        FastPayError::UnknownConsensusInstance(proposal.instance_id.clone())
                    })?;
                // Process lock certificates.
                for lock in locks {
                    lock.check(&self.committee)?;
                    match lock.value {
                        Value::Lock(Request {
                            account_id,
                            operation: Operation::LockInto { instance_id, owner },
                            sequence_number,
                        }) if instance_id == proposal.instance_id
                            && Some(&sequence_number)
                                == instance.sequence_numbers.get(&account_id) =>
                        {
                            // Update locking status for `account_id`.
                            instance.locked_accounts.insert(account_id, owner);
                            instance.participants.insert(owner);
                        }
                        _ => fp_bail!(FastPayError::InvalidConsensusOrder),
                    }
                }
                // Verify the signature and that the author of the signature is authorized.
                fp_ensure!(
                    instance.participants.contains(&owner),
                    FastPayError::InvalidConsensusOrder
                );
                signature.check(&proposal, owner)?;
                // Check validity of the proposal and obtain the corresponding requests.
                let requests = instance.make_requests(proposal.decision)?;
                // TODO: verify that `proposal.round` is "available".
                // Verify safety.
                if let Some(proposed) = &instance.proposed {
                    fp_ensure!(
                        (proposed.round == proposal.round
                            && proposed.decision == proposal.decision)
                            || proposed.round < proposal.round,
                        FastPayError::UnsafeConsensusProposal
                    );
                }
                if let Some(locked) = instance
                    .locked
                    .as_ref()
                    .and_then(|cert| cert.value.pre_commit_proposal())
                {
                    fp_ensure!(
                        locked.round < proposal.round && locked.decision == proposal.decision,
                        FastPayError::UnsafeConsensusProposal
                    );
                }
                // Update proposed decision.
                instance.proposed = Some(proposal.clone());
                // Vote in favor of pre-commit (aka lock).
                let value = Value::PreCommit { proposal, requests };
                let vote = Vote::new(value, &self.key_pair);
                Ok(ConsensusResponse::Vote(vote))
            }
            ConsensusOrder::HandlePreCommit { certificate } => {
                certificate.check(&self.committee)?;
                let (proposal, requests) = match certificate.value.clone() {
                    Value::PreCommit { proposal, requests } => (proposal, requests),
                    _ => fp_bail!(FastPayError::InvalidConsensusOrder),
                };
                let instance = self
                    .instances
                    .get_mut(&proposal.instance_id)
                    .ok_or_else(|| {
                        FastPayError::UnknownConsensusInstance(proposal.instance_id.clone())
                    })?;
                // Verify safety.
                if let Some(proposed) = &instance.proposed {
                    fp_ensure!(
                        proposed.round <= proposal.round,
                        FastPayError::UnsafeConsensusPreCommit
                    );
                }
                if let Some(locked) = instance
                    .locked
                    .as_ref()
                    .and_then(|cert| cert.value.pre_commit_proposal())
                {
                    fp_ensure!(
                        locked.round <= proposal.round,
                        FastPayError::UnsafeConsensusPreCommit
                    );
                }
                // Update locked decision.
                instance.locked = Some(certificate);
                // Vote in favor of commit.
                let value = Value::Commit { proposal, requests };
                let vote = Vote::new(value, &self.key_pair);
                Ok(ConsensusResponse::Vote(vote))
            }
            ConsensusOrder::HandleCommit { certificate, locks } => {
                certificate.check(&self.committee)?;
                let (proposal, requests) = match &certificate.value {
                    Value::Commit { proposal, requests } => (proposal, requests),
                    _ => fp_bail!(FastPayError::InvalidConsensusOrder),
                };
                // Success.
                // Only execute the requests in the commit once.
                let mut requests = {
                    if self.instances.contains_key(&proposal.instance_id) {
                        requests.clone()
                    } else {
                        Vec::new()
                    }
                };
                // Process lock certificates to add skip requests if needed.
                if let ConsensusDecision::Abort = &proposal.decision {
                    for lock in locks {
                        lock.check(&self.committee)?;
                        match lock.value {
                            Value::Lock(Request {
                                account_id,
                                operation:
                                    Operation::LockInto {
                                        instance_id,
                                        owner: _,
                                    },
                                sequence_number,
                            }) if instance_id == proposal.instance_id => {
                                requests.push(Request {
                                    account_id: account_id.clone(),
                                    operation: Operation::Skip,
                                    sequence_number,
                                });
                            }
                            _ => fp_bail!(FastPayError::InvalidConsensusOrder),
                        }
                    }
                }
                // Remove the consensus instance if needed.
                self.instances.remove(&proposal.instance_id);
                // Prepare cross-shard requests.
                let continuations = requests
                    .iter()
                    .map(|request| {
                        let shard_id = self.which_shard(&request.account_id);
                        CrossShardContinuation::Request {
                            shard_id,
                            request: Box::new(CrossShardRequest::ProcessConfirmedRequest {
                                request: request.clone(),
                                certificate: certificate.clone(),
                            }),
                        }
                    })
                    .collect();
                Ok(ConsensusResponse::Continuations(continuations))
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
            order.transaction_index == self.last_transaction_index.try_add_one()?,
            FastPayError::UnexpectedTransactionIndex
        );
        let recipient_balance = recipient_account.balance.try_add(order.amount.into())?;
        let last_transaction_index = self.last_transaction_index.try_add_one()?;
        recipient_account.balance = recipient_balance;
        recipient_account.synchronization_log.push(order);
        self.last_transaction_index = last_transaction_index;
        Ok(recipient_account.make_account_info(recipient))
    }

    fn handle_cross_shard_request(
        &mut self,
        request: CrossShardRequest,
    ) -> Result<(), FastPayError> {
        match request {
            CrossShardRequest::UpdateRecipient { certificate } => {
                let request = certificate
                    .value
                    .confirm_request()
                    .ok_or(FastPayError::InvalidCrossShardRequest)?;
                self.update_recipient_account(request.operation.clone(), certificate)
            }
            CrossShardRequest::DestroyAccount { account_id } => {
                fp_ensure!(self.in_shard(&account_id), FastPayError::WrongShard);
                self.accounts.remove(&account_id);
                Ok(())
            }
            CrossShardRequest::ProcessConfirmedRequest {
                request,
                certificate,
            } => {
                self.process_confirmed_request(request, certificate)?; // TODO: process continuations
                Ok(())
            }
        }
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
                fp_bail!(FastPayError::CertificateNotFound)
            }
        }
        if let Some(idx) = query.query_received_certificates_excluding_first_nth {
            response.queried_received_certificates = account.received_log[idx..].to_vec();
        }
        Ok(response)
    }
}

impl AuthorityState {
    pub fn new(
        committee: Committee,
        name: AuthorityName,
        key_pair: KeyPair,
        coconut_key_pair: Option<coconut::KeyPair>,
    ) -> Self {
        AuthorityState {
            committee,
            name,
            key_pair,
            coconut_key_pair,
            accounts: BTreeMap::new(),
            instances: BTreeMap::new(),
            last_transaction_index: SequenceNumber::new(),
            shard_id: 0,
            number_of_shards: 1,
        }
    }

    pub fn new_shard(
        committee: Committee,
        key_pair: KeyPair,
        coconut_key_pair: Option<coconut::KeyPair>,
        shard_id: u32,
        number_of_shards: u32,
    ) -> Self {
        AuthorityState {
            committee,
            name: key_pair.public(),
            key_pair,
            coconut_key_pair,
            accounts: BTreeMap::new(),
            instances: BTreeMap::new(),
            last_transaction_index: SequenceNumber::new(),
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
        let account = self
            .accounts
            .get(account_id)
            .ok_or_else(|| FastPayError::InactiveAccount(account_id.clone()))?;
        fp_ensure!(
            account.owner.is_some(),
            FastPayError::InactiveAccount(account_id.clone())
        );
        Ok(account)
    }

    #[cfg(test)]
    pub fn accounts_mut(&mut self) -> &mut BTreeMap<AccountId, AccountState> {
        &mut self.accounts
    }
}
