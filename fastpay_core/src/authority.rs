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
    /// The signature key of the authority.
    pub secret: KeyPair,
    /// Offchain states of FastPay accounts.
    pub accounts: BTreeMap<AccountId, AccountOffchainState>,
    /// The latest transaction index of the blockchain that the authority has seen.
    pub last_transaction_index: VersionNumber,
    /// The sharding ID of this authority shard. 0 if one shard.
    pub shard_id: ShardId,
    /// The number of shards. 1 if single shard.
    pub number_of_shards: u32,
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
    ) -> Result<(AccountInfoResponse, Option<CrossShardUpdate>), FastPayError>;

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

    /// Handle cross updates from another shard of the same authority.
    /// This relies on deliver-once semantics of a trusted channel between shards.
    fn handle_cross_shard_recipient_commit(
        &mut self,
        certificate: CertifiedTransferOrder,
    ) -> Result<(), FastPayError>;
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
        fp_ensure!(
            transfer.amount > Amount::zero(),
            FastPayError::IncorrectTransferAmount
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
                fp_ensure!(
                    account.balance >= transfer.amount.into(),
                    FastPayError::InsufficientFunding {
                        current_balance: account.balance
                    }
                );
                let signed_order = SignedTransferOrder::new(order, self.name, &self.secret);
                account.pending_confirmation = Some(signed_order);
                Ok(account.make_account_info(account_id))
            }
        }
    }

    /// Confirm a transfer.
    fn handle_confirmation_order(
        &mut self,
        confirmation_order: ConfirmationOrder,
    ) -> Result<(AccountInfoResponse, Option<CrossShardUpdate>), FastPayError> {
        let certificate = confirmation_order.transfer_certificate;
        // Check the certificate and retrieve the transfer data.
        fp_ensure!(
            self.in_shard(&certificate.value.transfer.account_id),
            FastPayError::WrongShard
        );
        certificate.check(&self.committee)?;
        let sender = certificate.value.transfer.account_id.clone();
        let owner = certificate.value.owner;
        let transfer = certificate.value.transfer.clone();

        // First we copy all relevant data from sender.
        let mut sender_account = self
            .accounts
            .entry(sender.clone())
            .or_insert_with(|| AccountOffchainState::new(owner));
        let mut sender_sequence_number = sender_account.next_sequence_number;
        let mut sender_balance = sender_account.balance;

        // Check and update the copied state
        if sender_sequence_number < transfer.sequence_number {
            fp_bail!(FastPayError::MissingEarlierConfirmations {
                current_sequence_number: sender_sequence_number
            });
        }
        if sender_sequence_number > transfer.sequence_number {
            // Transfer was already confirmed.
            return Ok((sender_account.make_account_info(sender), None));
        }
        sender_balance = sender_balance.try_sub(transfer.amount.into())?;
        sender_sequence_number = sender_sequence_number.increment()?;

        // Commit sender state back to the database (Must never fail!)
        sender_account.balance = sender_balance;
        sender_account.next_sequence_number = sender_sequence_number;
        sender_account.pending_confirmation = None;
        sender_account.confirmed_log.push(certificate.clone());
        let info = sender_account.make_account_info(sender);

        // Update FastPay recipient state locally or issue a cross-shard update (Must never fail!)
        let recipient = match transfer.recipient {
            Address::FastPay(recipient) => recipient,
            Address::Primary(_) => {
                // Nothing else to do for Primary recipients.
                return Ok((info, None));
            }
        };
        // If the recipient is in the same shard, read and update the account.
        if self.in_shard(&recipient) {
            let recipient_account = self
                .accounts
                .get_mut(&recipient)
                .ok_or(FastPayError::UnknownRecipientAccount(recipient))?;
            recipient_account.balance = recipient_account
                .balance
                .try_add(transfer.amount.into())
                .unwrap_or_else(|_| Balance::max());
            recipient_account.received_log.push(certificate);
            // Done updating recipient.
            return Ok((info, None));
        }
        // Otherwise, we need to send a cross-shard update.
        let cross_shard = Some(CrossShardUpdate {
            shard_id: self.which_shard(&recipient),
            transfer_certificate: certificate,
        });
        Ok((info, cross_shard))
    }

    // NOTE: Need to rely on deliver-once semantics from comms channel
    fn handle_cross_shard_recipient_commit(
        &mut self,
        certificate: CertifiedTransferOrder,
    ) -> Result<(), FastPayError> {
        // TODO: check certificate again?
        let transfer = &certificate.value.transfer;

        let recipient = match &transfer.recipient {
            Address::FastPay(recipient) => recipient,
            Address::Primary(_) => {
                fp_bail!(FastPayError::InvalidCrossShardUpdate);
            }
        };
        fp_ensure!(self.in_shard(recipient), FastPayError::WrongShard);
        let recipient_account = self
            .accounts
            .get_mut(recipient)
            .ok_or_else(|| FastPayError::UnknownRecipientAccount(recipient.clone()))?;
        recipient_account.balance = recipient_account
            .balance
            .try_add(transfer.amount.into())
            .unwrap_or_else(|_| Balance::max());
        recipient_account.received_log.push(certificate);
        Ok(())
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
            confirmed_log: Vec::new(),
            synchronization_log: Vec::new(),
            received_log,
        }
    }
}

impl AuthorityState {
    pub fn new(committee: Committee, name: AuthorityName, secret: KeyPair) -> Self {
        AuthorityState {
            committee,
            name,
            secret,
            accounts: BTreeMap::new(),
            last_transaction_index: VersionNumber::new(),
            shard_id: 0,
            number_of_shards: 1,
        }
    }

    pub fn new_shard(
        committee: Committee,
        name: AuthorityName,
        secret: KeyPair,
        shard_id: u32,
        number_of_shards: u32,
    ) -> Self {
        AuthorityState {
            committee,
            name,
            secret,
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
