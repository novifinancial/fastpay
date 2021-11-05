// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, error::FastPayError, messages::*};
use std::collections::BTreeSet;

/// State of a FastPay account.
#[derive(Debug, Default)]
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
    /// The indexing keys of all confirmed certificates as a receiver.
    pub received_keys: BTreeSet<(AccountId, SequenceNumber)>,
    /// All executed Primary synchronization orders for this recipient.
    pub synchronization_log: Vec<PrimarySynchronizationOrder>,
}

impl AccountState {
    pub(crate) fn make_account_info(&self, account_id: AccountId) -> AccountInfoResponse {
        AccountInfoResponse {
            account_id,
            owner: self.owner,
            balance: self.balance,
            next_sequence_number: self.next_sequence_number,
            pending: self.pending.clone(),
            count_received_certificates: self.received_log.len(),
            queried_certificate: None,
            queried_received_certificates: Vec::new(),
        }
    }

    pub fn new(owner: AccountOwner, balance: Balance) -> Self {
        Self {
            owner: Some(owner),
            balance,
            next_sequence_number: SequenceNumber::new(),
            pending: None,
            confirmed_log: Vec::new(),
            synchronization_log: Vec::new(),
            received_keys: BTreeSet::new(),
            received_log: Vec::new(),
        }
    }

    pub(crate) fn verify_linked_assets(
        account_id: &AccountId,
        assets: &[Asset],
    ) -> Result<Amount, FastPayError> {
        let mut total = Amount::zero();
        let mut t_seeds = BTreeSet::new();
        let mut z_seeds = BTreeSet::new();
        for asset in assets {
            let (id, value) = match asset {
                Asset::TransparentCoin(certificate) => {
                    if let Value::Coin(TransparentCoin {
                        account_id,
                        amount,
                        seed,
                    }) = &certificate.value
                    {
                        // Seeds must be distinct.
                        fp_ensure!(!t_seeds.contains(seed), FastPayError::InvalidCoin);
                        t_seeds.insert(*seed);
                        (account_id, *amount)
                    } else {
                        continue;
                    }
                }
                Asset::OpaqueCoin(OpaqueCoin {
                    id,
                    value,
                    public_seed,
                    ..
                }) => {
                    // Seeds must be distinct.
                    fp_ensure!(!z_seeds.contains(public_seed), FastPayError::InvalidCoin);
                    z_seeds.insert(*public_seed);
                    (id, *value)
                }
            };
            // Verify linked account.
            fp_ensure!(account_id == id, FastPayError::InvalidCoin);
            // Update source amount.
            total.try_add_assign(value)?;
        }
        Ok(total)
    }

    /// Verify that the operation is valid and return the value to certify.
    pub(crate) fn validate_operation(
        &self,
        request: Request,
        assets: &[Asset],
    ) -> Result<Value, FastPayError> {
        let value = match &request.operation {
            Operation::Transfer { amount, .. } => {
                fp_ensure!(
                    *amount > Amount::zero(),
                    FastPayError::IncorrectTransferAmount
                );
                fp_ensure!(
                    self.balance >= (*amount).into(),
                    FastPayError::InsufficientFunding {
                        current_balance: self.balance
                    }
                );
                Value::Confirm(request)
            }
            Operation::Spend {
                account_balance, ..
            } => {
                fp_ensure!(
                    self.balance >= (*account_balance).into(),
                    FastPayError::InsufficientFunding {
                        current_balance: self.balance
                    }
                );
                Value::Lock(request)
            }
            Operation::SpendAndTransfer { amount, .. } => {
                // Verify balance.
                let coin_total = Self::verify_linked_assets(&request.account_id, assets)?;
                let public_amount = amount.try_sub(coin_total)?;
                fp_ensure!(
                    self.balance >= public_amount.into(),
                    FastPayError::InsufficientFunding {
                        current_balance: self.balance
                    }
                );
                Value::Confirm(request)
            }
            Operation::OpenAccount { new_id, .. } => {
                let expected_id = request.account_id.make_child(request.sequence_number);
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
        Ok(value)
    }

    /// Execute the sender's side of the operation.
    pub(crate) fn apply_operation_as_sender(
        &mut self,
        operation: &Operation,
        certificate: Certificate,
    ) -> Result<(), FastPayError> {
        assert_eq!(
            &certificate.value.confirm_request().unwrap().operation,
            operation
        );
        match operation {
            Operation::OpenAccount { .. } => (),
            Operation::ChangeOwner { new_owner } => {
                self.owner = Some(*new_owner);
            }
            Operation::CloseAccount | Operation::SpendAndTransfer { .. } => {
                self.owner = None;
            }
            Operation::Transfer { amount, .. } => {
                self.balance.try_sub_assign((*amount).into())?;
            }
            Operation::Spend { .. } => {
                // impossible under BFT assumptions.
                unreachable!("Spend operation are never confirmed");
            }
        };
        self.confirmed_log.push(certificate);
        Ok(())
    }

    /// Execute the recipient's side of an operation.
    pub(crate) fn apply_operation_as_recipient(
        &mut self,
        operation: &Operation,
        certificate: Certificate,
    ) -> Result<(), FastPayError> {
        assert_eq!(
            &certificate.value.confirm_request().unwrap().operation,
            operation
        );
        let key = certificate.value.confirm_key().unwrap();
        if self.received_keys.contains(&key) {
            // Confirmation already happened.
            return Ok(());
        }
        match operation {
            Operation::Transfer { amount, .. } | Operation::SpendAndTransfer { amount, .. } => {
                self.balance = self
                    .balance
                    .try_add((*amount).into())
                    .unwrap_or_else(|_| Balance::max());
            }
            Operation::OpenAccount { new_owner, .. } => {
                assert!(self.owner.is_none()); // guaranteed under BFT assumptions.
                self.owner = Some(*new_owner);
            }
            _ => unreachable!("Not an operation with recipients"),
        }
        self.received_keys.insert(key);
        self.received_log.push(certificate);
        Ok(())
    }
}
