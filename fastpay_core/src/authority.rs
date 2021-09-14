// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, committee::Committee, error::FastPayError, messages::*};
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "unit_tests/authority_tests.rs"]
mod authority_tests;

/// State of an (offchain) FastPay account.
#[derive(Eq, PartialEq, Debug)]
pub struct AccountOffchainState {
    /// Owner of the account
    pub owner: AccountOwner,
    /// Balance of the FastPay account.
    pub balance: Balance,
    /// Sequence number tracking orders.
    pub next_sequence_number: SequenceNumber,
    /// Whether we have signed a transfer for this sequence number already.
    pub pending_confirmation: Option<SignedTransferOrder>,
    /// Whether we are in the process of confirming a transfer for this sequence number already.
    pub locked_confirmation: Option<CertifiedTransferOrder>,
    /// All confirmed certificates for this sender.
    pub confirmed_log: Vec<CertifiedTransferOrder>,
    /// All executed Primary synchronization orders for this recipient.
    pub synchronization_log: Vec<PrimarySynchronizationOrder>,
    /// All confirmed certificates as a receiver.
    pub received_log: Vec<CertifiedTransferOrder>,
}

pub struct AuthorityState {
    /// The name of this autority.
    pub name: AuthorityName,
    /// Committee of this FastPay instance.
    pub committee: Committee,
    /// The signature key pair of the authority.
    pub key_pair: KeyPair,
    /// Offchain states of FastPay accounts.
    pub accounts: BTreeMap<AccountId, AccountOffchainState>,
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
    /// Initiate a new transfer to a FastPay or Primary account.
    fn handle_transfer_order(
        &mut self,
        order: TransferOrder,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// Confirm a transfer to a FastPay or Primary account.
    fn handle_confirmation_order(
        &mut self,
        order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError>;

    /// Force synchronization to finalize transfers from Primary to FastPay.
    fn handle_primary_synchronization_order(
        &mut self,
        order: PrimarySynchronizationOrder,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// Handle information requests for this account.
    fn handle_account_info_request(
        &self,
        request: AccountInfoRequest,
    ) -> Result<AccountInfoResponse, FastPayError>;

    /// (Trusted) Try to update the recipient account in a confirmation order.
    /// Returns the next action to execute.
    fn update_recipient_account(
        &mut self,
        certificate: CertifiedTransferOrder,
    ) -> Result<CrossShardContinuation, FastPayError>;

    /// (Trusted) Try to confirm that a missing account was deleted, as part of a confirmation order.
    /// Returns the next action to execute.
    fn verify_account_deletion(
        &mut self,
        parent_id: AccountId,
        sequence_number: SequenceNumber,
        certificate: CertifiedTransferOrder,
    ) -> Result<CrossShardContinuation, FastPayError>;

    /// (Trusted) Update the sender account in a confirmation order. The confirmation of a
    /// certificate may be skipped if we were able to prove that the recipient account
    /// was deleted, or may be flagged to be retried if the recipient account does not exist yet.
    fn update_sender_account(
        &mut self,
        certificate: CertifiedTransferOrder,
        outcome: ConfirmationOutcome,
    ) -> Result<CrossShardContinuation, FastPayError>;
}

impl AuthorityState {
    /// Same as `verify_account_deletion` but first we verify if the account has a parent.
    /// Accounts without a parent (aka "root accounts") are created in the initial
    /// configuration and never deleted.
    fn verify_account_deletion_internal(
        &mut self,
        account_id: AccountId,
        certificate: CertifiedTransferOrder,
    ) -> Result<CrossShardContinuation, FastPayError> {
        assert_eq!(
            certificate.value.transfer.operation.recipient(),
            Some(&account_id)
        );
        match account_id.parent() {
            None => {
                // Recipient is not a removable account, so it should be created soon.
                // Client should retry confirmation later.
                let shard_id = self.which_shard(&certificate.value.transfer.account_id);
                let request = Box::new(CrossShardRequest::UpdateSenderAccount {
                    certificate,
                    outcome: ConfirmationOutcome::Retry,
                });
                Ok(CrossShardContinuation::Request { shard_id, request })
            }
            Some(parent) => {
                // Recipient is removable. Need to ask the shard of the parent.
                let shard_id = self.which_shard(&parent);
                let request = Box::new(CrossShardRequest::VerifyAccountDeletion {
                    parent_id: parent,
                    sequence_number: account_id.sequence_number().unwrap(),
                    certificate,
                });
                Ok(CrossShardContinuation::Request { shard_id, request })
            }
        }
    }
}

impl Authority for AuthorityState {
    /// Initiate a new transfer.
    fn handle_transfer_order(
        &mut self,
        order: TransferOrder,
    ) -> Result<AccountInfoResponse, FastPayError> {
        // Check the sender's signature and retrieve the transfer data.
        fp_ensure!(
            self.in_shard(&order.transfer.account_id),
            FastPayError::WrongShard
        );
        order.check_signature()?;
        let transfer = &order.transfer;
        let account_id = order.transfer.account_id.clone();
        fp_ensure!(
            transfer.sequence_number <= SequenceNumber::max(),
            FastPayError::InvalidSequenceNumber
        );
        match self.accounts.get_mut(&account_id) {
            None => fp_bail!(FastPayError::UnknownSenderAccount(account_id)),
            Some(account) => {
                fp_ensure!(account.owner == order.owner, FastPayError::InvalidOwner);
                if let Some(pending_confirmation) = &account.pending_confirmation {
                    fp_ensure!(
                        &pending_confirmation.value.transfer == transfer,
                        FastPayError::PreviousTransferMustBeConfirmedFirst {
                            pending_confirmation: pending_confirmation.value.clone()
                        }
                    );
                    // This exact transfer order was already signed. Return the previous value.
                    return Ok(account.make_account_info(account_id));
                }
                fp_ensure!(
                    account.next_sequence_number == transfer.sequence_number,
                    FastPayError::UnexpectedSequenceNumber
                );
                match &transfer.operation {
                    Operation::Payment { amount, .. } => {
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
                    }
                    Operation::CreateAccount { new_id, .. } => {
                        let expected_id = account_id.make_child(transfer.sequence_number);
                        fp_ensure!(
                            new_id == &expected_id,
                            FastPayError::InvalidNewAccountId(new_id.clone())
                        );
                    }
                    Operation::ChangeOwner { .. } => (), // Nothing to check.
                }
                let signed_order = SignedTransferOrder::new(order, &self.key_pair);
                account.pending_confirmation = Some(signed_order);
                Ok(account.make_account_info(account_id))
            }
        }
    }

    /// Confirm a transfer.
    fn handle_confirmation_order(
        &mut self,
        confirmation_order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, CrossShardContinuation), FastPayError> {
        let certificate = confirmation_order.transfer_certificate;
        // Check the certificate and retrieve the transfer data.
        fp_ensure!(
            self.in_shard(&certificate.value.transfer.account_id),
            FastPayError::WrongShard
        );
        certificate.check(&self.committee)?;
        let sender = certificate.value.transfer.account_id.clone();
        let transfer = certificate.value.transfer.clone();

        let mut sender_account = self
            .accounts
            .get_mut(&sender)
            .ok_or_else(|| FastPayError::UnknownSenderAccount(sender.clone()))?;
        let sender_sequence_number = sender_account.next_sequence_number;
        let info = sender_account.make_account_info(sender.clone());

        if sender_sequence_number < transfer.sequence_number {
            fp_bail!(FastPayError::MissingEarlierConfirmations {
                current_sequence_number: sender_sequence_number
            });
        }
        if sender_sequence_number > transfer.sequence_number {
            // Transfer was already confirmed.
            return Ok((info, CrossShardContinuation::Done));
        }
        if let Some(previous) = &sender_account.locked_confirmation {
            // Confirmation is in progress.
            assert!(certificate.value.transfer == previous.value.transfer); // guaranteed under BFT assumptions.
            return Ok((info, CrossShardContinuation::Done));
        }
        // Lock sender's account during confirmation.
        sender_account.locked_confirmation = Some(certificate.clone());
        let info = sender_account.make_account_info(sender.clone());

        if let Some(recipient) = transfer.operation.recipient() {
            if !self.in_shard(recipient) || !self.accounts.contains_key(recipient) {
                // If the recipient in a different shard, or does not seem to exist locally,
                // initiate proper cross-shard communication, starting with the recipient's
                // account.
                let shard_id = self.which_shard(recipient);
                let cont = CrossShardContinuation::Request {
                    shard_id,
                    request: Box::new(CrossShardRequest::UpdateRecipientAccount { certificate }),
                };
                return Ok((info, cont));
            }
        }

        // Otherwise, call handlers directly to spare some messaging.
        self.update_recipient_account(certificate.clone())?;
        self.update_sender_account(certificate, ConfirmationOutcome::Complete)?;

        // Return a more accurate account info in this case.
        let account = self
            .accounts
            .get(&sender)
            .ok_or_else(|| FastPayError::UnknownSenderAccount(sender.clone()))?;
        let info = account.make_account_info(sender);
        Ok((info, CrossShardContinuation::Done))
    }

    fn update_recipient_account(
        &mut self,
        certificate: CertifiedTransferOrder,
    ) -> Result<CrossShardContinuation, FastPayError> {
        let transfer = &certificate.value.transfer;
        // Execute the recipient's side of the operation.
        match &transfer.operation {
            Operation::Payment {
                recipient: Address::FastPay(recipient),
                amount,
                ..
            } => {
                fp_ensure!(self.in_shard(recipient), FastPayError::WrongShard);
                let account = match self.accounts.get_mut(recipient) {
                    Some(account) => account,
                    None => {
                        // Recipient account does not exist here. We must investigate
                        // if the account was deleted, or if it is still waiting to be
                        // created.
                        return self
                            .verify_account_deletion_internal(recipient.clone(), certificate);
                    }
                };
                account.balance = account
                    .balance
                    .try_add((*amount).into())
                    .unwrap_or_else(|_| Balance::max());
                account.received_log.push(certificate.clone());
            }
            Operation::CreateAccount { new_id, new_owner } => {
                fp_ensure!(self.in_shard(new_id), FastPayError::WrongShard);
                assert!(!self.accounts.contains_key(new_id)); // guaranteed under BFT assumptions.
                let mut account = AccountOffchainState::new(*new_owner);
                account.received_log.push(certificate.clone());
                self.accounts.insert(new_id.clone(), account);
            }
            Operation::Payment {
                recipient: Address::Primary(_),
                ..
            }
            | Operation::ChangeOwner { .. } => (),
        }

        // Send response to sender's shard.
        let shard_id = self.which_shard(&transfer.account_id);
        let request = Box::new(CrossShardRequest::UpdateSenderAccount {
            certificate,
            outcome: ConfirmationOutcome::Complete,
        });
        Ok(CrossShardContinuation::Request { shard_id, request })
    }

    /// Try to determine if the missing account (parent_id, sequence_number) was deleted
    /// or if it could be created in the future.
    fn verify_account_deletion(
        &mut self,
        parent_id: AccountId,
        sequence_number: SequenceNumber,
        certificate: CertifiedTransferOrder,
    ) -> Result<CrossShardContinuation, FastPayError> {
        fp_ensure!(self.in_shard(&parent_id), FastPayError::WrongShard);
        match self.accounts.get(&parent_id) {
            Some(account) => {
                let shard_id = self.which_shard(&certificate.value.transfer.account_id);
                let outcome = if account.next_sequence_number > sequence_number {
                    // The account used to exist but it was deleted and will never re-appear.
                    ConfirmationOutcome::Cancel
                } else {
                    // Sequence number of parent shows that the account could be created in the future.
                    ConfirmationOutcome::Retry
                };
                let request = Box::new(CrossShardRequest::UpdateSenderAccount {
                    certificate,
                    outcome,
                });
                Ok(CrossShardContinuation::Request { shard_id, request })
            }

            None => {
                // The parent is missing. Since created account starts at sequence number
                // 0, the answer is the same as the parent.
                self.verify_account_deletion_internal(parent_id, certificate)
            }
        }
    }

    fn update_sender_account(
        &mut self,
        certificate: CertifiedTransferOrder,
        outcome: ConfirmationOutcome,
    ) -> Result<CrossShardContinuation, FastPayError> {
        let transfer = &certificate.value.transfer;
        let sender = &certificate.value.transfer.account_id;
        fp_ensure!(self.in_shard(sender), FastPayError::WrongShard);
        let mut account = self
            .accounts
            .get_mut(sender)
            .ok_or(FastPayError::InvalidCrossShardRequest)?;

        match outcome {
            ConfirmationOutcome::Complete => {
                // Execute the sender's side of the operation.
                match &transfer.operation {
                    Operation::Payment { amount, .. } => {
                        account.balance = account.balance.try_sub((*amount).into())?;
                    }
                    Operation::ChangeOwner { new_owner } => {
                        account.owner = *new_owner;
                    }
                    Operation::CreateAccount { .. } => (),
                }
                // Advance to next sequence number.
                account.next_sequence_number = account.next_sequence_number.increment()?;
                account.pending_confirmation = None;
                account.confirmed_log.push(certificate);
                // Release lock on the sender account.
                account.locked_confirmation = None;
            }
            ConfirmationOutcome::Cancel => {
                // Do not execute the operation.
                // Advance to next sequence number.
                account.next_sequence_number = account.next_sequence_number.increment()?;
                account.pending_confirmation = None;
                account.confirmed_log.push(certificate);
                // Release lock on the sender account.
                account.locked_confirmation = None;
            }
            ConfirmationOutcome::Retry => {
                // Do not execute the operation.
                // Do not advance the sequence number.
                // Release lock on the sender account.
                account.locked_confirmation = None;
            }
        }
        Ok(CrossShardContinuation::Done)
    }

    /// Finalize a transfer from Primary.
    fn handle_primary_synchronization_order(
        &mut self,
        order: PrimarySynchronizationOrder,
    ) -> Result<AccountInfoResponse, FastPayError> {
        // Update recipient state; note that the blockchain client is trusted.
        let recipient = order.recipient.clone();
        fp_ensure!(self.in_shard(&recipient), FastPayError::WrongShard);

        let recipient_account = self
            .accounts
            .get_mut(&recipient)
            .ok_or_else(|| FastPayError::UnknownRecipientAccount(recipient.clone()))?;
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

    fn handle_account_info_request(
        &self,
        request: AccountInfoRequest,
    ) -> Result<AccountInfoResponse, FastPayError> {
        fp_ensure!(self.in_shard(&request.account_id), FastPayError::WrongShard);
        let account = self.account_state(&request.account_id)?;
        let mut response = account.make_account_info(request.account_id);
        if let Some(seq) = request.request_sequence_number {
            if let Some(cert) = account.confirmed_log.get(usize::from(seq)) {
                response.requested_certificate = Some(cert.clone());
            } else {
                fp_bail!(FastPayError::CertificateNotfound)
            }
        }
        if let Some(idx) = request.request_received_transfers_excluding_first_nth {
            response.requested_received_transfers = account.received_log[idx..].to_vec();
        }
        Ok(response)
    }
}

impl AccountOffchainState {
    pub fn new(owner: AccountOwner) -> Self {
        Self {
            owner,
            balance: Balance::zero(),
            next_sequence_number: SequenceNumber::new(),
            pending_confirmation: None,
            locked_confirmation: None,
            confirmed_log: Vec::new(),
            synchronization_log: Vec::new(),
            received_log: Vec::new(),
        }
    }

    fn make_account_info(&self, account_id: AccountId) -> AccountInfoResponse {
        AccountInfoResponse {
            account_id,
            balance: self.balance,
            next_sequence_number: self.next_sequence_number,
            pending_confirmation: self.pending_confirmation.clone(),
            locked_confirmation: self.locked_confirmation.clone(),
            requested_certificate: None,
            requested_received_transfers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn new_with_balance(
        owner: AccountOwner,
        balance: Balance,
        received_log: Vec<CertifiedTransferOrder>,
    ) -> Self {
        Self {
            owner,
            balance,
            next_sequence_number: SequenceNumber::new(),
            pending_confirmation: None,
            locked_confirmation: None,
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

    fn account_state(&self, account_id: &AccountId) -> Result<&AccountOffchainState, FastPayError> {
        self.accounts
            .get(account_id)
            .ok_or_else(|| FastPayError::UnknownSenderAccount(account_id.clone()))
    }

    #[cfg(test)]
    pub fn accounts_mut(&mut self) -> &mut BTreeMap<AccountId, AccountOffchainState> {
        &mut self.accounts
    }
}
