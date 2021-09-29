// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, error::FastPayError, messages::*};

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
            received_log: Vec::new(),
        }
    }

    /// Verify that the operation is valid and return the value to certify.
    pub(crate) fn validate_operation(
        &self,
        request: Request,
        assets: &[Certificate],
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
                let mut amount = *amount;
                // Verify source coins.
                for coin in assets {
                    match &coin.value {
                        Value::Coin(coin) if coin.account_id == request.account_id => {
                            amount.try_sub_assign(coin.amount)?;
                        }
                        _ => fp_bail!(FastPayError::InvalidCoin),
                    }
                }
                // Verify balance.
                fp_ensure!(
                    self.balance >= amount.into(),
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
        self.received_log.push(certificate);
        Ok(())
    }
}
