// Copyright (c) Facebook Inc.
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

    /// Handle information queries for this account.
    fn handle_account_info_query(
        &mut self,
        query: AccountInfoQuery,
    ) -> AsyncResult<AccountInfoResponse, FastPayError>;
}

pub struct ClientState<AuthorityClient> {
    /// Our offchain account id.
    account_id: AccountId,
    /// Our signature key.
    key_pair: KeyPair,
    /// Our FastPay committee.
    committee: Committee,
    /// How to talk to this committee.
    authority_clients: HashMap<AuthorityName, AuthorityClient>,
    /// Expected sequence number for the next certified request.
    /// This is also the number of request certificates that we have created.
    next_sequence_number: SequenceNumber,
    /// Pending request.
    pending_request: Option<RequestOrder>,
    /// Pending new key pair.
    pending_key_pair: Option<KeyPair>,

    // The remaining fields are used to minimize networking, and may not always be persisted locally.
    /// Request certificates that we have created ("sent").
    /// Normally, `sent_certificates` should contain one certificate for each index in `0..next_sequence_number`.
    sent_certificates: Vec<Certificate>,
    /// Known received certificates, indexed by account_id and sequence number.
    /// TODO: API to search and download yet unknown `received_certificates`.
    received_certificates: BTreeMap<(AccountId, SequenceNumber), Certificate>,
    /// The known spendable balance (including a possible initial funding, excluding unknown sent
    /// or received certificates).
    balance: Balance,
}

// Operations are considered successful when they successfully reach a quorum of authorities.
pub trait Client {
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

    /// Receive money from FastPay.
    fn receive_from_fastpay(&mut self, certificate: Certificate)
        -> AsyncResult<(), failure::Error>;

    /// Send money to a FastPay account.
    /// Do not check balance. (This may block the client)
    /// Do not confirm the transaction.
    fn transfer_to_fastpay_unsafe_unconfirmed(
        &mut self,
        amount: Amount,
        recipient: AccountId,
        user_data: UserData,
    ) -> AsyncResult<Certificate, failure::Error>;

    /// Find how much money we can spend.
    /// TODO: Currently, this value only reflects received transfers that were
    /// locally processed by `receive_from_fastpay`.
    fn get_spendable_amount(&mut self) -> AsyncResult<Amount, failure::Error>;
}

impl<A> ClientState<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        key_pair: KeyPair,
        committee: Committee,
        authority_clients: HashMap<AuthorityName, A>,
        next_sequence_number: SequenceNumber,
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
            pending_request: None,
            pending_key_pair: None,
            sent_certificates,
            received_certificates: received_certificates
                .into_iter()
                .filter_map(|cert| Some((cert.value.confirm_key()?, cert)))
                .collect(),
            balance,
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn next_sequence_number(&self) -> SequenceNumber {
        self.next_sequence_number
    }

    pub fn balance(&self) -> Balance {
        self.balance
    }

    pub fn pending_request(&self) -> &Option<RequestOrder> {
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

    /// Try to find a certificate for the given account_id and sequence number.
    fn query(&mut self, sequence_number: SequenceNumber) -> AsyncResult<Certificate, FastPayError> {
        Box::pin(async move {
            let query = AccountInfoQuery {
                account_id: self.account_id.clone(),
                query_sequence_number: Some(sequence_number),
                query_received_requests_excluding_first_nth: None,
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
            Err(FastPayError::ErrorWhileRequestingCertificate)
        })
    }
}

/// Used for communicate_requests
#[derive(Clone)]
enum CommunicateAction {
    SendOrder(RequestOrder),
    SynchronizeNextSequenceNumber(SequenceNumber),
}

impl<A> ClientState<A>
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
            query_received_requests_excluding_first_nth: None,
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

    /// Find the highest balance that is backed by a quorum of authorities.
    /// NOTE: This is only reliable in the synchronous model, with a sufficient timeout value.
    #[cfg(test)]
    async fn get_strong_majority_balance(&mut self) -> Balance {
        let query = AccountInfoQuery {
            account_id: self.account_id.clone(),
            query_sequence_number: None,
            query_received_requests_excluding_first_nth: None,
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
    }

    /// Execute a sequence of actions in parallel for a quorum of authorities.
    async fn communicate_with_quorum<'a, V, F>(
        &'a mut self,
        execute: F,
    ) -> Result<Vec<V>, failure::Error>
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
                        bail!(
                            "Failed to communicate with a quorum of authorities: {}",
                            err
                        );
                    }
                }
            }
        }

        bail!("Failed to communicate with a quorum of authorities (multiple errors)");
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
            CommunicateAction::SendOrder(order) => order.request.sequence_number,
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
        let votes = self
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
                        query_received_requests_excluding_first_nth: None,
                    };
                    let response = client.handle_account_info_query(query).await?;
                    let current_sequence_number = response.next_sequence_number;
                    // Download each missing certificate in reverse order using the downloader.
                    let mut missing_certificates = Vec::new();
                    let mut number = target_sequence_number.decrement();
                    while let Ok(value) = number {
                        if value < current_sequence_number {
                            break;
                        }
                        let certificate = handle
                            .query(value)
                            .await
                            .map_err(|_| FastPayError::ErrorWhileRequestingCertificate)??;
                        missing_certificates.push(certificate);
                        number = value.decrement();
                    }
                    // Send all missing confirmation orders.
                    missing_certificates.reverse();
                    for certificate in missing_certificates {
                        client
                            .handle_confirmation_order(ConfirmationOrder::new(certificate))
                            .await?;
                    }
                    // Send the request order (if any) and return a vote.
                    if let CommunicateAction::SendOrder(order) = action {
                        let result = client.handle_request_order(order).await;
                        match result {
                            Ok(AccountInfoResponse {
                                pending_confirmation: Some(signed_order),
                                ..
                            }) => {
                                fp_ensure!(
                                    signed_order.authority == name,
                                    FastPayError::ErrorWhileProcessingRequestOrder
                                );
                                signed_order.check(committee)?;
                                return Ok(Some(signed_order));
                            }
                            Err(err) => return Err(err),
                            _ => return Err(FastPayError::ErrorWhileProcessingRequestOrder),
                        }
                    }
                    Ok(None)
                })
            })
            .await?;
        // Terminate downloader task and retrieve the content of the cache.
        handle.stop().await?;
        let mut certificates: Vec<_> = task.await.unwrap().filter_map(Result::ok).collect();
        if let CommunicateAction::SendOrder(order) = action {
            let certificate = Certificate {
                value: Value::Confirm(order.request),
                signatures: votes
                    .into_iter()
                    .filter_map(|vote| match vote {
                        Some(signed_order) => {
                            Some((signed_order.authority, signed_order.signature))
                        }
                        None => None,
                    })
                    .collect(),
            };
            // Certificate is valid because
            // * `communicate_with_quorum` ensured a sufficient "weight" of (non-error) answers were returned by authorities.
            // * each answer is a vote signed by the expected authority.
            certificates.push(certificate);
        }
        Ok(certificates)
    }

    /// Make sure we have all our certificates with sequence number
    /// in the range 0..self.next_sequence_number
    async fn download_sent_certificates(&self) -> Result<Vec<Certificate>, FastPayError> {
        let mut requester = CertificateRequester::new(
            self.committee.clone(),
            self.authority_clients.values().cloned().collect(),
            self.account_id.clone(),
        );
        let known_sequence_numbers: BTreeSet<_> = self
            .sent_certificates
            .iter()
            .filter_map(|cert| cert.value.confirm_sequence_number())
            .collect();
        let mut sent_certificates = self.sent_certificates.clone();
        let mut number = SequenceNumber::from(0);
        while number < self.next_sequence_number {
            if !known_sequence_numbers.contains(&number) {
                let certificate = requester.query(number).await?;
                sent_certificates.push(certificate);
            }
            number = number.increment().unwrap_or_else(|_| SequenceNumber::max());
        }
        sent_certificates.sort_by_key(|cert| cert.value.confirm_sequence_number().unwrap());
        Ok(sent_certificates)
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
        let safe_amount = self.get_spendable_amount().await?;
        ensure!(
            amount <= safe_amount,
            "Requested amount ({:?}) is not backed by sufficient funds ({:?})",
            amount,
            safe_amount
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
        let order = RequestOrder::new(request, &self.key_pair);
        let certificate = self
            .execute_request(order, /* with_confirmation */ true)
            .await?;
        Ok(certificate)
    }

    /// Update our view of sent certificates. Adjust the local balance and the next sequence number accordingly.
    /// NOTE: This is only useful in the eventuality of missing local data.
    /// We assume certificates to be valid and sent by us, and their sequence numbers to be unique.
    fn update_sent_certificates(
        &mut self,
        sent_certificates: Vec<Certificate>,
    ) -> Result<(), FastPayError> {
        let mut new_balance = self.balance;
        let mut new_next_sequence_number = self.next_sequence_number;
        for new_cert in &sent_certificates {
            let request = match &new_cert.value {
                Value::Confirm(r) => r,
                _ => continue,
            };
            match &request.operation {
                Operation::Transfer { amount, .. } => {
                    new_balance = new_balance.try_sub((*amount).into())?;
                }
                Operation::OpenAccount { .. }
                | Operation::CloseAccount
                | Operation::ChangeOwner { .. } => (),
            }
            if request.sequence_number >= new_next_sequence_number {
                assert_eq!(
                    request.sequence_number, new_next_sequence_number,
                    "New certificates should be given in order"
                );
                if let Operation::ChangeOwner { new_owner } = &request.operation {
                    // TODO: add client support for initiating key rotations
                    // TODO: support handing over the account to someone else.
                    // TODO: crash resistance + key storage
                    let key_pair = std::mem::take(&mut self.pending_key_pair)
                        .expect("We are rotating the key for ourselves.");
                    assert_eq!(new_owner, &key_pair.public(), "Idem");
                    self.key_pair = key_pair;
                }
                new_next_sequence_number = request
                    .sequence_number
                    .increment()
                    .unwrap_or_else(|_| SequenceNumber::max());
            }
        }
        for old_cert in &self.sent_certificates {
            let request = match &old_cert.value {
                Value::Confirm(r) => r,
                _ => continue,
            };
            match &request.operation {
                Operation::Transfer { amount, .. } => {
                    new_balance = new_balance.try_add((*amount).into())?;
                }
                Operation::OpenAccount { .. }
                | Operation::CloseAccount
                | Operation::ChangeOwner { .. } => (),
            }
        }
        // Atomic update
        self.sent_certificates = sent_certificates;
        self.balance = new_balance;
        self.next_sequence_number = new_next_sequence_number;
        // Sanity check
        assert_eq!(
            self.sent_certificates.len() as u64,
            u64::from(self.next_sequence_number),
        );
        Ok(())
    }

    /// Execute (or retry) a request order. Update local balance.
    async fn execute_request(
        &mut self,
        order: RequestOrder,
        with_confirmation: bool,
    ) -> Result<Certificate, failure::Error> {
        ensure!(
            self.pending_request.is_none()
                || self.pending_request.as_ref().unwrap().request == order.request,
            "Client state has a different pending request",
        );
        ensure!(
            order.request.sequence_number == self.next_sequence_number,
            "Unexpected sequence number"
        );
        self.pending_request = Some(order.clone());
        let new_sent_certificates = self
            .communicate_requests(
                self.account_id.clone(),
                self.sent_certificates.clone(),
                CommunicateAction::SendOrder(order.clone()),
            )
            .await?;
        assert_eq!(
            new_sent_certificates.last().unwrap().value,
            Value::Confirm(order.request)
        );
        // Clear `pending_request` and update `sent_certificates`,
        // `balance`, and `next_sequence_number`. (Note that if we were using persistent
        // storage, we should ensure update atomicity in the eventuality of a crash.)
        self.pending_request = None;
        self.update_sent_certificates(new_sent_certificates)?;
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
}

impl<A> Client for ClientState<A>
where
    A: AuthorityClient + Send + Sync + Clone + 'static,
{
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

    fn get_spendable_amount(&mut self) -> AsyncResult<Amount, failure::Error> {
        Box::pin(async move {
            if let Some(order) = self.pending_request.clone() {
                // Finish executing the previous request.
                self.execute_request(order, /* with_confirmation */ false)
                    .await?;
            }
            if self.sent_certificates.len() < self.next_sequence_number.into() {
                // Recover missing sent certificates.
                let new_sent_certificates = self.download_sent_certificates().await?;
                self.update_sent_certificates(new_sent_certificates)?;
            }
            let amount = if self.balance < Balance::zero() {
                Amount::zero()
            } else {
                Amount::try_from(self.balance).unwrap_or_else(|_| std::u64::MAX.into())
            };
            Ok(amount)
        })
    }

    fn receive_from_fastpay(
        &mut self,
        certificate: Certificate,
    ) -> AsyncResult<(), failure::Error> {
        Box::pin(async move {
            certificate.check(&self.committee)?;
            let request = match &certificate.value {
                Value::Confirm(r) => r,
                _ => return Ok(()),
            };
            let account_id = &request.account_id;
            match &request.operation {
                Operation::Transfer { recipient, .. } => {
                    ensure!(
                        recipient == &Address::FastPay(self.account_id.clone()), // TODO: avoid copy
                        "Request should be received by us."
                    );
                }
                Operation::OpenAccount { .. }
                | Operation::CloseAccount
                | Operation::ChangeOwner { .. } => {
                    // TODO: decide what to do
                }
            }
            self.communicate_requests(
                account_id.clone(),
                vec![certificate.clone()],
                CommunicateAction::SynchronizeNextSequenceNumber(
                    request.sequence_number.increment()?,
                ),
            )
            .await?;
            // Everything worked: update the local balance.
            if let btree_map::Entry::Vacant(entry) = self
                .received_certificates
                .entry(certificate.value.confirm_key().unwrap())
            {
                match &request.operation {
                    Operation::Transfer { amount, .. } => {
                        self.balance = self.balance.try_add((*amount).into())?;
                    }
                    Operation::OpenAccount { .. }
                    | Operation::CloseAccount
                    | Operation::ChangeOwner { .. } => (),
                }
                entry.insert(certificate);
            }
            Ok(())
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
            let order = RequestOrder::new(request, &self.key_pair);
            let new_certificate = self
                .execute_request(order, /* with_confirmation */ false)
                .await?;
            Ok(new_certificate)
        })
    }
}
