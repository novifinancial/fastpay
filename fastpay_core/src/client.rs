// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, committee::Committee, downloader::*, error::FastPayError, messages::*};
use failure::{bail, ensure};
use futures::{future, StreamExt};
use rand::seq::SliceRandom;
use std::{
    collections::{btree_map, BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
};

#[cfg(test)]
#[path = "unit_tests/client_tests.rs"]
mod client_tests;

pub type AsyncResult<'a, T, E> = future::BoxFuture<'a, Result<T, E>>;

/// How to communicate with an authority.
pub trait AuthorityClient {
    /// Initiate a new transfer to a FastPay or Primary account.
    fn handle_request_order(
        &mut self,
        order: RequestOrder,
    ) -> AsyncResult<AccountInfoResponse, FastPayError>;

    /// Confirm a request to a FastPay or Primary account.
    fn handle_confirmation_order(
        &mut self,
        order: ConfirmationOrder,
    ) -> AsyncResult<AccountInfoResponse, FastPayError>;

    /// Confirm a request to a FastPay or Primary account.
    fn handle_coin_creation_order(
        &mut self,
        order: CoinCreationOrder,
    ) -> AsyncResult<CoinCreationResponse, FastPayError>;

    /// Handle information queries for this account.
    fn handle_account_info_query(
        &mut self,
        query: AccountInfoQuery,
    ) -> AsyncResult<AccountInfoResponse, FastPayError>;
}

/// How to communicate with an FastPay account across all the authorities. As a rule,
/// operations are considered successful (and communication may stop) when they succeeed
/// in gathering a quorum of responses.
pub trait AccountClient {
    /// Send money to a FastPay account.
    fn transfer_to_fastpay(
        &mut self,
        amount: Amount,
        recipient: AccountId,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Send money to a Primary account.
    fn transfer_to_primary(
        &mut self,
        amount: Amount,
        recipient: PrimaryAddress,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Process confirmed operation for which this account is a recipient.
    fn receive_confirmation(&mut self, certificate: Certificate)
        -> AsyncResult<(), failure::Error>;

    /// Process an asset linked top this account.
    fn receive_asset(&mut self, asset: Asset) -> AsyncResult<(), failure::Error>;

    /// Rotate the key of the account.
    fn rotate_key_pair(&mut self, key_pair: KeyPair) -> AsyncResult<Certificate, failure::Error>;

    /// Transfer ownership of the account.
    fn transfer_ownership(
        &mut self,
        new_owner: AccountOwner,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Open a new account with a derived UID.
    fn open_account(&mut self, new_owner: AccountOwner)
        -> AsyncResult<Certificate, failure::Error>;

    /// Close the account (and lose everything in it!!)
    fn close_account(&mut self) -> AsyncResult<Certificate, failure::Error>;

    /// Spend (i.e. lock) the account in order to create coins later.
    fn spend_unsafe(
        &mut self,
        account_balance: Amount,
        description_hash: HashValue,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Create new coins using previously spent (i.e. locked) accounts.
    fn create_coins(
        &mut self,
        description: CoinCreationDescription,
        new_opaque_coins: Vec<(OpaqueCoin, coconut::OutputAttribute)>,
        locked_accounts: Vec<Certificate>,
    ) -> AsyncResult<Vec<Asset>, failure::Error>;

    /// Spend a single account and create new coins.
    fn spend_and_create_coins(
        &mut self,
        new_transparent_coins: Vec<TransparentCoin>,
        new_opaque_coins: Vec<OpaqueCoin>,
    ) -> AsyncResult<Vec<Asset>, failure::Error>;

    /// Spend the account and transfer the value to a receiver.
    fn spend_and_transfer(
        &mut self,
        recipient: Address,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Send money to a FastPay account.
    /// Do not check balance. (This may block the client)
    /// Do not confirm the transaction.
    fn transfer_to_fastpay_unsafe_unconfirmed(
        &mut self,
        amount: Amount,
        recipient: AccountId,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Compute a safe (i.e. pessimistic) balance by synchronizing our "sent" certificates
    /// with authorities, and otherwise using local data on received transfers (i.e.
    /// certificates that were locally processed by `receive_from_fastpay`).
    fn synchronize_balance(&mut self) -> AsyncResult<Balance, failure::Error>;

    /// Return the value of the known coins attached to this account.
    fn get_coins_value(&self) -> Result<Amount, failure::Error>;

    /// Find the highest balance that is backed by a quorum of authorities.
    /// NOTE: This is only safe in the synchronous model, assuming a sufficient timeout value.
    fn query_strong_majority_balance(&mut self) -> future::BoxFuture<Balance>;
}

/// The status of the last request order that we have sent, if any.
#[derive(Debug, Clone)]
pub enum PendingRequest {
    /// No request.
    None,
    /// A "regular" request meant to be confirmed.
    Regular(RequestOrder),
    /// A "locking" request that cannot be confirmed.
    Locking(RequestOrder),
}

/// Reference implementation of the `AccountClient` trait using many instances of
/// some `AuthorityClient` implementation for communication.
pub struct AccountClientState<AuthorityClient> {
    /// The offchain account id.
    account_id: AccountId,
    /// The current signature key, if we own this account.
    key_pair: Option<KeyPair>,
    /// The FastPay committee.
    committee: Committee,
    /// How to talk to this committee.
    authority_clients: HashMap<AuthorityName, AuthorityClient>,
    /// Expected sequence number for the next certified request.
    /// This is also the number of request certificates that we have created.
    next_sequence_number: SequenceNumber,
    /// Pending request.
    pending_request: PendingRequest,
    /// Proof that this account was locked / spent.
    lock_certificate: Option<Certificate>,
    /// Known key pairs (past and future).
    known_key_pairs: BTreeMap<AccountOwner, KeyPair>,
    /// The coins linked to this account.
    coins: Vec<Asset>,

    // The remaining fields are used to minimize networking, and may not always be persisted locally.
    /// Confirmed requests that we have created ("sent") and already included in the state
    /// of this account client. Certificate at index `i` should have sequence number `i`.
    /// When no certificate is pending/missing, `sent_certificates` should be of size `next_sequence_number`.
    sent_certificates: Vec<Certificate>,
    /// Known received certificates, indexed by account_id and sequence number.
    received_certificates: BTreeMap<(AccountId, SequenceNumber), Certificate>,
    /// The known spendable balance (including a possible initial funding for testing
    /// purposes, excluding unknown sent or received certificates).
    balance: Balance,
    /// Support synchronization of received certificates.
    received_certificate_trackers: HashMap<AuthorityName, usize>,
}

impl<A> AccountClientState<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        key_pair: Option<KeyPair>,
        committee: Committee,
        authority_clients: HashMap<AuthorityName, A>,
        next_sequence_number: SequenceNumber,
        coins: Vec<Asset>,
        sent_certificates: Vec<Certificate>,
        received_certificates: Vec<Certificate>,
        balance: Balance,
    ) -> Self {
        Self {
            account_id,
            key_pair,
            committee,
            authority_clients,
            next_sequence_number,
            pending_request: PendingRequest::None,
            known_key_pairs: BTreeMap::new(),
            coins,
            lock_certificate: None,
            sent_certificates,
            received_certificates: received_certificates
                .into_iter()
                .filter_map(|cert| Some((cert.value.confirm_key()?, cert)))
                .collect(),
            received_certificate_trackers: HashMap::new(),
            balance,
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn owner(&self) -> Option<AccountOwner> {
        self.key_pair.as_ref().map(|kp| kp.public())
    }

    pub fn key_pair(&self) -> Option<&KeyPair> {
        self.key_pair.as_ref()
    }

    pub fn next_sequence_number(&self) -> SequenceNumber {
        self.next_sequence_number
    }

    pub fn coins(&self) -> &Vec<Asset> {
        &self.coins
    }

    pub fn balance(&self) -> Balance {
        self.balance
    }

    pub fn pending_request(&self) -> &PendingRequest {
        &self.pending_request
    }

    pub fn sent_certificates(&self) -> &Vec<Certificate> {
        &self.sent_certificates
    }

    pub fn received_certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.received_certificates.values()
    }
}

#[derive(Clone)]
struct CertificateRequester<A> {
    committee: Committee,
    authority_clients: Vec<A>,
    account_id: AccountId,
}

impl<A> CertificateRequester<A> {
    fn new(committee: Committee, authority_clients: Vec<A>, account_id: AccountId) -> Self {
        Self {
            committee,
            authority_clients,
            account_id,
        }
    }
}

impl<A> Requester for CertificateRequester<A>
where
    A: AuthorityClient + Send + Sync + 'static + Clone,
{
    type Key = SequenceNumber;
    type Value = Result<Certificate, FastPayError>;

    /// Try to find a (confirmation) certificate for the given account_id and sequence number.
    fn query(&mut self, sequence_number: SequenceNumber) -> AsyncResult<Certificate, FastPayError> {
        Box::pin(async move {
            let query = AccountInfoQuery {
                account_id: self.account_id.clone(),
                query_sequence_number: Some(sequence_number),
                query_received_certificates_excluding_first_nth: None,
            };
            // Sequentially try each authority in random order.
            self.authority_clients.shuffle(&mut rand::thread_rng());
            for client in self.authority_clients.iter_mut() {
                let result = client.handle_account_info_query(query.clone()).await;
                if let Ok(AccountInfoResponse {
                    queried_certificate: Some(certificate),
                    ..
                }) = &result
                {
                    if certificate.check(&self.committee).is_ok() {
                        if let Value::Confirm(request) = &certificate.value {
                            if request.account_id == self.account_id
                                && request.sequence_number == sequence_number
                            {
                                return Ok(certificate.clone());
                            }
                        }
                    }
                }
            }
            Err(FastPayError::ClientErrorWhileRequestingCertificate)
        })
    }
}

/// Used for communicate_requests
#[derive(Clone)]
enum CommunicateAction {
    ConfirmOrder(RequestOrder),
    LockOrder(RequestOrder),
    SynchronizeNextSequenceNumber(SequenceNumber),
}

impl<A> AccountClientState<A>
where
    A: AuthorityClient + Send + Sync + 'static + Clone,
{
    #[cfg(test)]
    async fn query_certificate(
        &mut self,
        account_id: AccountId,
        sequence_number: SequenceNumber,
    ) -> Result<Certificate, FastPayError> {
        CertificateRequester::new(
            self.committee.clone(),
            self.authority_clients.values().cloned().collect(),
            account_id,
        )
        .query(sequence_number)
        .await
    }

    /// Find the highest sequence number that is known to a quorum of authorities.
    /// NOTE: This is only reliable in the synchronous model, with a sufficient timeout value.
    #[cfg(test)]
    async fn get_strong_majority_sequence_number(
        &mut self,
        account_id: AccountId,
    ) -> SequenceNumber {
        let query = AccountInfoQuery {
            account_id,
            query_sequence_number: None,
            query_received_certificates_excluding_first_nth: None,
        };
        let numbers: futures::stream::FuturesUnordered<_> = self
            .authority_clients
            .iter_mut()
            .map(|(name, client)| {
                let fut = client.handle_account_info_query(query.clone());
                async move {
                    match fut.await {
                        Ok(info) => Some((*name, info.next_sequence_number)),
                        _ => None,
                    }
                }
            })
            .collect();
        self.committee.get_strong_majority_lower_bound(
            numbers.filter_map(|x| async move { x }).collect().await,
        )
    }

    /// Execute a sequence of actions in parallel for a quorum of authorities.
    async fn communicate_with_quorum<'a, V, F>(
        &'a mut self,
        execute: F,
    ) -> Result<Vec<V>, Option<FastPayError>>
    where
        F: Fn(AuthorityName, &'a mut A) -> AsyncResult<'a, V, FastPayError> + Clone,
    {
        let committee = &self.committee;
        let authority_clients = &mut self.authority_clients;
        let mut responses: futures::stream::FuturesUnordered<_> = authority_clients
            .iter_mut()
            .map(|(name, client)| {
                let execute = execute.clone();
                async move { (*name, execute(*name, client).await) }
            })
            .collect();

        let mut values = Vec::new();
        let mut value_score = 0;
        let mut error_scores = HashMap::new();
        while let Some((name, result)) = responses.next().await {
            match result {
                Ok(value) => {
                    values.push(value);
                    value_score += committee.weight(&name);
                    if value_score >= committee.quorum_threshold() {
                        // Success!
                        return Ok(values);
                    }
                }
                Err(err) => {
                    let entry = error_scores.entry(err.clone()).or_insert(0);
                    *entry += committee.weight(&name);
                    if *entry >= committee.validity_threshold() {
                        // At least one honest node returned this error.
                        // No quorum can be reached, so return early.
                        return Err(Some(err));
                    }
                }
            }
        }

        // No specific error is available to report reliably.
        Err(None)
    }

    /// Broadcast confirmation orders and optionally one more request order.
    /// The corresponding sequence numbers should be consecutive and increasing.
    async fn communicate_requests(
        &mut self,
        account_id: AccountId,
        known_certificates: Vec<Certificate>,
        action: CommunicateAction,
    ) -> Result<Vec<Certificate>, failure::Error> {
        let target_sequence_number = match &action {
            CommunicateAction::ConfirmOrder(order) | CommunicateAction::LockOrder(order) => {
                order.value.request.sequence_number
            }
            CommunicateAction::SynchronizeNextSequenceNumber(seq) => *seq,
        };
        let requester = CertificateRequester::new(
            self.committee.clone(),
            self.authority_clients.values().cloned().collect(),
            account_id.clone(),
        );
        let (task, mut handle) = Downloader::start(
            requester,
            known_certificates.into_iter().filter_map(|cert| {
                let request = cert.value.confirm_request()?;
                if request.account_id == account_id {
                    Some((request.sequence_number, Ok(cert)))
                } else {
                    None
                }
            }),
        );
        let committee = self.committee.clone();
        let result = self
            .communicate_with_quorum(|name, client| {
                let mut handle = handle.clone();
                let action = action.clone();
                let committee = &committee;
                let account_id = account_id.clone();
                Box::pin(async move {
                    // Figure out which certificates this authority is missing.
                    let query = AccountInfoQuery {
                        account_id,
                        query_sequence_number: None,
                        query_received_certificates_excluding_first_nth: None,
                    };
                    let response = client.handle_account_info_query(query).await?;
                    let current_sequence_number = response.next_sequence_number;
                    // Download each missing certificate in reverse order using the downloader.
                    let mut missing_certificates = Vec::new();
                    let mut number = target_sequence_number.try_sub_one();
                    while let Ok(value) = number {
                        if value < current_sequence_number {
                            break;
                        }
                        let certificate = handle
                            .query(value)
                            .await
                            .map_err(|_| FastPayError::ClientErrorWhileRequestingCertificate)??;
                        missing_certificates.push(certificate);
                        number = value.try_sub_one();
                    }
                    // Send all missing confirmation orders.
                    missing_certificates.reverse();
                    for certificate in missing_certificates {
                        client
                            .handle_confirmation_order(ConfirmationOrder::new(certificate))
                            .await?;
                    }
                    // Send the request order (if any) and return a vote.
                    if let CommunicateAction::ConfirmOrder(order)
                    | CommunicateAction::LockOrder(order) = action
                    {
                        let result = client.handle_request_order(order).await;
                        match result {
                            Ok(AccountInfoResponse {
                                pending: Some(vote),
                                ..
                            }) => {
                                fp_ensure!(
                                    vote.authority == name,
                                    FastPayError::ClientErrorWhileProcessingRequestOrder
                                );
                                vote.check(committee)?;
                                return Ok(Some(vote));
                            }
                            Err(err) => return Err(err),
                            _ => return Err(FastPayError::ClientErrorWhileProcessingRequestOrder),
                        }
                    }
                    Ok(None)
                })
            })
            .await;
        let votes = match result {
            Ok(votes) => votes,
            Err(Some(FastPayError::InactiveAccount(id)))
                if id == account_id
                    && matches!(action, CommunicateAction::SynchronizeNextSequenceNumber(_)) =>
            {
                // The account is visibly not active (yet or any more) so there is no need
                // to synchronize sequence numbers.
                return Ok(Vec::new());
            }
            Err(Some(err)) => bail!(
                "Failed to communicate with a quorum of authorities: {}",
                err
            ),
            Err(None) => {
                bail!("Failed to communicate with a quorum of authorities (multiple errors)")
            }
        };
        // Terminate downloader task and retrieve the content of the cache.
        handle.stop().await?;
        let mut certificates: Vec<_> = task.await.unwrap().filter_map(Result::ok).collect();
        let signatures: Vec<_> = votes
            .into_iter()
            .filter_map(|vote| match vote {
                Some(vote) => Some((vote.authority, vote.signature)),
                None => None,
            })
            .collect();
        match action {
            CommunicateAction::ConfirmOrder(order) => {
                let certificate = Certificate {
                    value: Value::Confirm(order.value.request),
                    signatures,
                };
                // Certificate is valid because
                // * `communicate_with_quorum` ensured a sufficient "weight" of (non-error) answers were returned by authorities.
                // * each answer is a vote signed by the expected authority.
                certificates.push(certificate);
            }
            CommunicateAction::LockOrder(order) => {
                let certificate = Certificate {
                    value: Value::Lock(order.value.request),
                    signatures,
                };
                certificates.push(certificate);
            }
            CommunicateAction::SynchronizeNextSequenceNumber(_) => (),
        }
        Ok(certificates)
    }

    /// Make sure we have all our certificates with sequence number
    /// in the range 0..self.next_sequence_number
    async fn download_missing_sent_certificates(&mut self) -> Result<(), FastPayError> {
        let mut requester = CertificateRequester::new(
            self.committee.clone(),
            self.authority_clients.values().cloned().collect(),
            self.account_id.clone(),
        );
        while self.sent_certificates.len() < self.next_sequence_number.into() {
            let certificate = requester
                .query(SequenceNumber::from(self.sent_certificates.len() as u64))
                .await?;
            self.add_sent_certificate(certificate)?;
        }
        Ok(())
    }

    /// Attempt to download new received certificates.
    async fn synchronize_received_certificates(&mut self) -> Result<(), failure::Error> {
        let account_id = self.account_id.clone();
        let trackers = self.received_certificate_trackers.clone();
        let committee = self.committee.clone();
        let result = self
            .communicate_with_quorum(|name, client| {
                let committee = &committee;
                let account_id = &account_id;
                let tracker = *trackers.get(&name).unwrap_or(&0);
                Box::pin(async move {
                    // Retrieve new received certificates from this authority.
                    let query = AccountInfoQuery {
                        account_id: account_id.clone(),
                        query_sequence_number: None,
                        query_received_certificates_excluding_first_nth: Some(tracker),
                    };
                    let response = client.handle_account_info_query(query).await?;
                    for certificate in &response.queried_received_certificates {
                        certificate.check(committee)?;
                        let request = certificate
                            .value
                            .confirm_request()
                            .ok_or(FastPayError::ClientErrorWhileRequestingCertificate)?;
                        let recipient = request
                            .operation
                            .recipient()
                            .ok_or(FastPayError::ClientErrorWhileRequestingCertificate)?;
                        fp_ensure!(
                            recipient == account_id,
                            FastPayError::ClientErrorWhileRequestingCertificate
                        );
                    }
                    Ok((name, response))
                })
            })
            .await;
        match result {
            Ok(responses) => {
                for (name, response) in responses {
                    // Process received certificates.
                    for certificate in response.queried_received_certificates {
                        self.receive_confirmation(certificate).await.unwrap_or(());
                    }
                    // Update tracker.
                    self.received_certificate_trackers
                        .insert(name, response.count_received_certificates);
                }
            }
            Err(Some(FastPayError::InactiveAccount(id))) if id == account_id => {
                // The account is visibly not active (yet or any more) so there is no need
                // to synchronize received certificates.
                return Ok(());
            }
            Err(Some(err)) => bail!(
                "Failed to communicate with a quorum of authorities: {}",
                err
            ),
            Err(None) => {
                bail!("Failed to communicate with a quorum of authorities (multiple errors)")
            }
        };
        Ok(())
    }

    /// Send money to a FastPay or Primary recipient.
    async fn transfer(
        &mut self,
        amount: Amount,
        recipient: Address,
        user_data: UserData,
    ) -> Result<Certificate, failure::Error> {
        // Trying to overspend may block the account. To prevent this, we compare with
        // the balance as we know it.
        let balance = self.synchronize_balance().await?;
        ensure!(
            Balance::from(amount) <= balance,
            "Requested amount ({}) is not backed by sufficient funds ({})",
            amount,
            balance
        );
        let request = Request {
            account_id: self.account_id.clone(),
            operation: Operation::Transfer {
                recipient,
                amount,
                user_data,
            },
            sequence_number: self.next_sequence_number,
        };
        let order = self.make_request_order(request)?;
        let certificate = self
            .execute_regular_request(order, /* with_confirmation */ true)
            .await?;
        Ok(certificate)
    }

    fn update_sent_certificates(
        &mut self,
        sent_certificates: Vec<Certificate>,
    ) -> Result<(), FastPayError> {
        let n = self.sent_certificates.len();
        for (i, certificate) in sent_certificates.into_iter().enumerate() {
            if i < n {
                assert_eq!(certificate.value, self.sent_certificates[i].value);
            } else {
                self.add_sent_certificate(certificate)?;
            }
        }
        Ok(())
    }

    fn add_sent_certificate(&mut self, certificate: Certificate) -> Result<(), FastPayError> {
        let request = certificate
            .value
            .confirm_request()
            .expect("was expecting a confirmation certificate");
        assert_eq!(
            u64::from(request.sequence_number),
            self.sent_certificates.len() as u64
        );
        // Execute operation locally.
        match &request.operation {
            Operation::Transfer { amount, .. } => {
                self.balance.try_sub_assign((*amount).into())?;
            }
            Operation::ChangeOwner { new_owner } => match self.known_key_pairs.entry(*new_owner) {
                btree_map::Entry::Occupied(kp) => {
                    let old = std::mem::take(&mut self.key_pair);
                    self.key_pair = Some(kp.remove());
                    if let Some(kp) = old {
                        self.known_key_pairs.insert(kp.public(), kp);
                    }
                }
                btree_map::Entry::Vacant(_) => {
                    let old = std::mem::take(&mut self.key_pair);
                    if let Some(kp) = old {
                        self.known_key_pairs.insert(kp.public(), kp);
                    }
                }
            },
            Operation::CloseAccount
            | Operation::Spend { .. }
            | Operation::SpendAndTransfer { .. } => {
                self.key_pair = None;
            }
            Operation::OpenAccount { .. } => (),
        }
        // Record certificate.
        self.sent_certificates.push(certificate);
        let next_sequence_number = SequenceNumber::from(self.sent_certificates.len() as u64);
        if self.next_sequence_number < next_sequence_number {
            self.next_sequence_number = next_sequence_number;
        }
        Ok(())
    }

    /// Execute (or retry) a regular request order. Update local balance.
    async fn execute_regular_request(
        &mut self,
        order: RequestOrder,
        with_confirmation: bool,
    ) -> Result<Certificate, failure::Error> {
        ensure!(
            matches!(&self.pending_request, PendingRequest::None)
                || matches!(&self.pending_request, PendingRequest::Regular(o) if o.value.request == order.value.request),
            "Client state has a different pending request",
        );
        ensure!(
            order.value.request.sequence_number == self.next_sequence_number,
            "Unexpected sequence number"
        );
        self.download_missing_sent_certificates().await?;
        self.pending_request = PendingRequest::Regular(order.clone());
        let certificates = self
            .communicate_requests(
                self.account_id.clone(),
                self.sent_certificates.clone(),
                CommunicateAction::ConfirmOrder(order.clone()),
            )
            .await?;
        self.update_sent_certificates(certificates)?;
        assert_eq!(
            self.sent_certificates
                .last()
                .expect("last order should be confirmed now")
                .value,
            Value::Confirm(order.value.request)
        );
        self.pending_request = PendingRequest::None;
        // Confirm last request certificate if needed.
        if with_confirmation {
            self.communicate_requests(
                self.account_id.clone(),
                self.sent_certificates.clone(),
                CommunicateAction::SynchronizeNextSequenceNumber(self.next_sequence_number),
            )
            .await?;
        }
        Ok(self.sent_certificates.last().unwrap().clone())
    }

    /// Execute (or retry) a locking request order. Update local balance.
    async fn execute_locking_request(
        &mut self,
        order: RequestOrder,
    ) -> Result<Certificate, failure::Error> {
        match &self.lock_certificate {
            Some(certificate) => {
                ensure!(
                    matches!(&certificate.value, Value::Lock(r) if &order.value.request == r),
                    "Account has already been locked for a different operation."
                );
                return Ok(certificate.clone());
            }
            None => (),
        }
        ensure!(
            matches!(&self.pending_request, PendingRequest::None)
                || matches!(&self.pending_request, PendingRequest::Locking(o) if o.value.request == order.value.request),
            "Client state has a different pending request",
        );
        ensure!(
            order.value.request.sequence_number == self.next_sequence_number,
            "Unexpected sequence number"
        );
        self.download_missing_sent_certificates().await?;
        self.pending_request = PendingRequest::Locking(order.clone());
        let mut certificates = self
            .communicate_requests(
                self.account_id.clone(),
                self.sent_certificates.clone(),
                CommunicateAction::LockOrder(order.clone()),
            )
            .await?;
        self.lock_certificate = certificates.pop();
        self.update_sent_certificates(certificates)?;
        assert_eq!(
            self.lock_certificate
                .as_ref()
                .expect("last order should be locked now")
                .value,
            Value::Lock(order.value.request)
        );
        self.pending_request = PendingRequest::None;
        Ok(self.lock_certificate.as_ref().unwrap().clone())
    }

    /// Execute (or retry) a coin creation order.
    async fn execute_coin_creation(
        &mut self,
        order: CoinCreationOrder,
        new_opaque_coins: Vec<(OpaqueCoin, coconut::OutputAttribute)>,
    ) -> Result<Vec<Asset>, failure::Error> {
        let targets = order.description.targets.clone();
        let coin_num = targets.len();
        let committee = self.committee.clone();
        let result = self
            .communicate_with_quorum(|name, client| {
                let order = order.clone();
                let committee = committee.clone();
                let targets = targets.clone();
                let output_attributes = new_opaque_coins
                    .iter()
                    .map(|(_, attribute)| attribute.clone())
                    .collect::<Vec<_>>();
                Box::pin(async move {
                    let response = client.handle_coin_creation_order(order).await?;
                    fp_ensure!(
                        response.votes.len() == coin_num,
                        FastPayError::ClientErrorWhileProcessingCoinCreationOrder
                    );
                    for (i, vote) in response.votes.iter().enumerate() {
                        fp_ensure!(
                            vote.authority == name,
                            FastPayError::ClientErrorWhileProcessingCoinCreationOrder
                        );
                        fp_ensure!(
                            matches!(&vote.value, Value::Coin(coin) if coin == &targets[i]),
                            FastPayError::ClientErrorWhileProcessingCoinCreationOrder
                        );
                        vote.check(&committee)?;
                    }
                    let (index, verified_shares) = match response.blinded_coins {
                        None => (/* unused */ 0, Vec::new()),
                        Some(blinded_coins) => {
                            let setup = committee
                                .coconut_setup
                                .as_ref()
                                .ok_or(FastPayError::ClientErrorWhileProcessingCoinCreationOrder)?;
                            fp_ensure!(
                                blinded_coins.len() == output_attributes.len(),
                                FastPayError::ClientErrorWhileProcessingCoinCreationOrder
                            );
                            let (index, public_key) = &setup
                                .authorities
                                .get(&name)
                                .ok_or(FastPayError::ClientErrorWhileProcessingCoinCreationOrder)?;
                            let shares = blinded_coins.unblind(public_key, &output_attributes);
                            for (share, attributes) in shares.iter().zip(output_attributes.iter()) {
                                fp_ensure!(
                                    share.plain_verify(
                                        &setup.parameters,
                                        public_key,
                                        attributes.value,
                                        attributes.seed,
                                        attributes.key
                                    ),
                                    FastPayError::ClientErrorWhileProcessingCoinCreationOrder
                                );
                            }
                            (*index, shares)
                        }
                    };
                    Ok((response.votes, index, verified_shares))
                })
            })
            .await;
        let responses = match result {
            Ok(responses) => responses,
            Err(Some(err)) => bail!(
                "Failed to communicate with a quorum of authorities: {}",
                err
            ),
            Err(None) => {
                bail!("Failed to communicate with a quorum of authorities (multiple errors)")
            }
        };
        let mut builders = targets
            .into_iter()
            .map(|coin| SignatureAggregator::new(Value::Coin(coin), &committee))
            .collect::<Vec<_>>();
        let mut coin_shares = std::iter::repeat_with(Vec::new)
            .take(new_opaque_coins.len())
            .collect::<Vec<_>>();
        let mut coins = Vec::new();
        for (votes, index, shares) in responses {
            // Votes for transparent coins.
            for (i, vote) in votes.into_iter().enumerate() {
                if let Some(certificate) = builders[i].append(vote.authority, vote.signature)? {
                    coins.push(Asset::TransparentCoin { certificate });
                }
            }
            // Organize Lagrange shares of opaque coins.
            for (i, share) in shares.into_iter().enumerate() {
                coin_shares[i].push((share, index));
            }
        }
        for (shares, (value, _)) in coin_shares.into_iter().zip(new_opaque_coins.into_iter()) {
            let credential = coconut::Coin::aggregate(&shares);
            coins.push(Asset::OpaqueCoin { value, credential });
        }
        Ok(coins)
    }

    fn make_request_order_with_assets(
        &self,
        request: Request,
        assets: Vec<Asset>,
    ) -> Result<RequestOrder, failure::Error> {
        let key_pair = self.key_pair.as_ref().ok_or_else(|| {
            failure::format_err!("Cannot make request for an account that we don't own")
        })?;
        Ok(RequestOrder::new(request.into(), key_pair, assets))
    }

    fn make_request_order(&self, request: Request) -> Result<RequestOrder, failure::Error> {
        self.make_request_order_with_assets(request, Vec::new())
    }
}

impl<A> AccountClient for AccountClientState<A>
where
    A: AuthorityClient + Send + Sync + Clone + 'static,
{
    fn query_strong_majority_balance(&mut self) -> future::BoxFuture<Balance> {
        Box::pin(async move {
            let query = AccountInfoQuery {
                account_id: self.account_id.clone(),
                query_sequence_number: None,
                query_received_certificates_excluding_first_nth: None,
            };
            let numbers: futures::stream::FuturesUnordered<_> = self
                .authority_clients
                .iter_mut()
                .map(|(name, client)| {
                    let fut = client.handle_account_info_query(query.clone());
                    async move {
                        match fut.await {
                            Ok(info) => Some((*name, info.balance)),
                            _ => None,
                        }
                    }
                })
                .collect();
            self.committee.get_strong_majority_lower_bound(
                numbers.filter_map(|x| async move { x }).collect().await,
            )
        })
    }

    fn transfer_to_fastpay(
        &mut self,
        amount: Amount,
        recipient: AccountId,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(self.transfer(amount, Address::FastPay(recipient), user_data))
    }

    fn transfer_to_primary(
        &mut self,
        amount: Amount,
        recipient: PrimaryAddress,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(self.transfer(amount, Address::Primary(recipient), user_data))
    }

    fn synchronize_balance(&mut self) -> AsyncResult<Balance, failure::Error> {
        Box::pin(async move {
            match self.pending_request.clone() {
                PendingRequest::Regular(order) => {
                    // Finish executing the previous request.
                    self.execute_regular_request(order, /* with_confirmation */ false)
                        .await?;
                }
                PendingRequest::Locking(order) => {
                    // Finish executing the previous request.
                    self.execute_locking_request(order).await?;
                }
                PendingRequest::None => (),
            }
            self.synchronize_received_certificates().await?;
            self.download_missing_sent_certificates().await?;
            Ok(self.balance)
        })
    }

    fn receive_asset(&mut self, asset: Asset) -> AsyncResult<(), failure::Error> {
        Box::pin(async move {
            asset.check(&self.committee)?;
            ensure!(
                asset.account_id()? == &self.account_id,
                "TransparentCoin is not linked to this account"
            );
            self.coins.push(asset);
            Ok(())
        })
    }

    fn receive_confirmation(
        &mut self,
        certificate: Certificate,
    ) -> AsyncResult<(), failure::Error> {
        Box::pin(async move {
            let request = certificate.value.confirm_request().ok_or_else(|| {
                failure::format_err!("Was expecting a confirmed account operation")
            })?;
            let account_id = &request.account_id;
            ensure!(
                request.operation.recipient() == Some(&self.account_id),
                "Request should be received by us."
            );
            self.communicate_requests(
                account_id.clone(),
                vec![certificate.clone()],
                CommunicateAction::SynchronizeNextSequenceNumber(
                    request.sequence_number.try_add_one()?,
                ),
            )
            .await?;
            // Everything worked: update the local balance.
            if let btree_map::Entry::Vacant(entry) = self
                .received_certificates
                .entry(certificate.value.confirm_key().unwrap())
            {
                if let Some(amount) = request.operation.received_amount() {
                    self.balance.try_add_assign(amount.into())?;
                }
                entry.insert(certificate);
            }
            Ok(())
        })
    }

    fn rotate_key_pair(&mut self, key_pair: KeyPair) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let new_owner = key_pair.public();
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::ChangeOwner { new_owner },
                sequence_number: self.next_sequence_number,
            };
            self.known_key_pairs.insert(key_pair.public(), key_pair);
            let order = self.make_request_order(request)?;

            let certificate = self
                .execute_regular_request(order, /* with_confirmation */ true)
                .await?;
            Ok(certificate)
        })
    }

    fn transfer_ownership(
        &mut self,
        new_owner: AccountOwner,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::ChangeOwner { new_owner },
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order(request)?;
            let certificate = self
                .execute_regular_request(order, /* with_confirmation */ true)
                .await?;
            Ok(certificate)
        })
    }

    fn open_account(
        &mut self,
        new_owner: AccountOwner,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let new_id = self.account_id.make_child(self.next_sequence_number);
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::OpenAccount { new_id, new_owner },
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order(request)?;
            let certificate = self
                .execute_regular_request(order, /* with_confirmation */ true)
                .await?;
            Ok(certificate)
        })
    }

    fn close_account(&mut self) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::CloseAccount,
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order(request)?;
            let certificate = self
                .execute_regular_request(order, /* with_confirmation */ true)
                .await?;
            Ok(certificate)
        })
    }

    /// Spend the account with new coins in mind.
    fn spend_unsafe(
        &mut self,
        account_balance: Amount,
        description_hash: HashValue,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let balance = self.synchronize_balance().await?;
            ensure!(
                Balance::from(account_balance) <= balance,
                "Suggested balance ({}) does not match available funds ({})",
                account_balance,
                balance
            );
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::Spend {
                    account_balance,
                    description_hash,
                },
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order_with_assets(request, self.coins.clone())?;
            self.execute_locking_request(order).await
        })
    }

    /// Spend the account and create new coins.
    fn create_coins(
        &mut self,
        description: CoinCreationDescription,
        new_opaque_coins: Vec<(OpaqueCoin, coconut::OutputAttribute)>,
        locks: Vec<Certificate>,
    ) -> AsyncResult<Vec<Asset>, failure::Error> {
        Box::pin(async move {
            let creation_order = CoinCreationOrder { description, locks };
            let coins = self
                .execute_coin_creation(creation_order, new_opaque_coins)
                .await?;
            Ok(coins)
        })
    }

    fn spend_and_create_coins(
        &mut self,
        new_transparent_coins: Vec<TransparentCoin>,
        new_opaque_coins: Vec<OpaqueCoin>,
    ) -> AsyncResult<Vec<Asset>, failure::Error> {
        Box::pin(async move {
            let account_balance = self.synchronize_balance().await?;
            let mut amount =
                Amount::try_from(account_balance.try_add(self.get_coins_value()?.into())?)?;
            // Check description for new transparent coins.
            {
                let mut seeds = BTreeSet::new();
                for coin in &new_transparent_coins {
                    ensure!(
                        !seeds.contains(&coin.seed),
                        "TransparentCoin seeds must be unique"
                    );
                    seeds.insert(coin.seed);
                    amount.try_sub_assign(coin.amount).map_err(|_| {
                        failure::format_err!("Insufficient balance to create coins")
                    })?;
                }
            }
            // Check description for new opaque coins.
            {
                let mut seeds = BTreeSet::new();
                for coin in &new_opaque_coins {
                    ensure!(
                        !seeds.contains(&coin.public_seed),
                        "TransparentCoin seeds must be unique"
                    );
                    seeds.insert(coin.public_seed);
                    amount.try_sub_assign(coin.amount).map_err(|_| {
                        failure::format_err!("Insufficient balance to create coins")
                    })?;
                }
            }
            let account_balance = Amount::try_from(account_balance)?;
            let transparent_coins = self
                .coins
                .iter()
                .filter_map(|asset| match asset {
                    Asset::TransparentCoin { certificate } => Some(certificate.clone()),
                    _ => None,
                })
                .collect();
            let opaque_coin_public_seeds = self
                .coins
                .iter()
                .filter_map(|asset| match asset {
                    Asset::OpaqueCoin {
                        value:
                            OpaqueCoin {
                                id, public_seed, ..
                            },
                        ..
                    } => {
                        assert_eq!(id, &self.account_id);
                        Some(*public_seed)
                    }
                    _ => None,
                })
                .collect();
            let opaque_coins = self
                .coins
                .iter()
                .filter_map(|asset| match asset {
                    Asset::OpaqueCoin { credential, .. } => Some(credential.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let source = CoinCreationSource {
                account_id: self.account_id.clone(),
                account_balance,
                transparent_coins,
                opaque_coin_public_seeds,
            };
            let (coconut_request, new_opaque_coins_with_attributes) =
                if opaque_coins.is_empty() && new_opaque_coins.is_empty() {
                    (None, Vec::new())
                } else {
                    let setup = self
                        .committee
                        .coconut_setup
                        .as_ref()
                        .expect("Coconut must be configured to use opaque coins");
                    let input_attributes = self
                        .coins
                        .iter()
                        .filter_map(|asset| match asset {
                            Asset::OpaqueCoin { value, .. } => Some(value.make_input_attribute()),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    let mut new_opaque_coins_with_attributes = Vec::new();
                    let mut output_attributes = Vec::new();
                    for coin in new_opaque_coins {
                        let attribute = coin.make_output_attribute();
                        output_attributes.push(attribute.clone());
                        new_opaque_coins_with_attributes.push((coin, attribute));
                    }
                    let request = coconut::CoinsRequest::new(
                        coconut::rand::thread_rng(),
                        &setup.parameters,
                        &setup.verification_key,
                        &opaque_coins,
                        &input_attributes,
                        &output_attributes,
                    );
                    (Some(request), new_opaque_coins_with_attributes)
                };
            let description = CoinCreationDescription {
                sources: vec![source],
                targets: new_transparent_coins,
                coconut_request,
            };
            let description_hash = HashValue::new(&description);
            let lock_certificate = self.spend_unsafe(account_balance, description_hash).await?;
            self.create_coins(
                description,
                new_opaque_coins_with_attributes,
                vec![lock_certificate],
            )
            .await
        })
    }

    fn get_coins_value(&self) -> Result<Amount, failure::Error> {
        let mut amount = Amount::from(0);
        for coin in &self.coins {
            let v = coin
                .value()
                .map_err(|_| failure::format_err!("Client state contains invalid coins"))?;
            amount.try_add_assign(v)?;
        }
        Ok(amount)
    }

    fn spend_and_transfer(
        &mut self,
        recipient: Address,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let amount = {
                let balance = self.synchronize_balance().await?;
                Amount::try_from(balance.try_add(self.get_coins_value()?.into())?)?
            };
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::SpendAndTransfer {
                    recipient,
                    amount,
                    user_data,
                },
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order_with_assets(request, self.coins.clone())?;
            let certificate = self
                .execute_regular_request(order, /* with_confirmation */ true)
                .await?;
            Ok(certificate)
        })
    }

    fn transfer_to_fastpay_unsafe_unconfirmed(
        &mut self,
        amount: Amount,
        recipient: AccountId,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error> {
        Box::pin(async move {
            let request = Request {
                account_id: self.account_id.clone(),
                operation: Operation::Transfer {
                    recipient: Address::FastPay(recipient),
                    amount,
                    user_data,
                },
                sequence_number: self.next_sequence_number,
            };
            let order = self.make_request_order(request)?;
            let new_certificate = self
                .execute_regular_request(order, /* with_confirmation */ false)
                .await?;
            Ok(new_certificate)
        })
    }
}
