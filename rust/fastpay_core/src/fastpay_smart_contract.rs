// Copyright (c) Calibra Research
// SPDX-License-Identifier: Apache-2.0

use super::base_types::*;
use super::committee::Committee;
use super::messages::*;
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "unit_tests/fastpay_smart_contract_tests.rs"]
mod fastpay_smart_contract_tests;

// -- BEGIN FILE fastpay_smart_contract_state --

#[derive(Eq, PartialEq, Clone, Hash, Debug)]
pub struct AccountOnchainState {
    /// Prevent spending actions from this account to Libra to be redeemed more than once.
    /// It is the responsability of the owner of the account to redeem the previous action
    /// before initiating a new one. Otherwise, money can be lost.
    last_redeemed: Option<SequenceNumber>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct FastPaySmartContractState {
    /// Committee of this FastPay instance.
    committee: Committee,
    /// Onchain states of FastPay smart contract.
    pub accounts: BTreeMap<FastPayAddress, AccountOnchainState>,
    /// Libra coins in the smart contract.
    total_balance: Amount,
    /// The latest transaction index included in the blockchain.
    pub last_transaction_index: VersionNumber,
    /// Transactions included in the blockchain.
    pub blockchain: Vec<FundingTransaction>,
}
// -- END FILE --

// -- BEGIN FILE fastpay_smart_contract --
pub trait FastPaySmartContract {
    /// Initiate a transfer from Libra to FastPay.
    fn handle_funding_transaction(
        &mut self,
        transaction: FundingTransaction,
    ) -> Result<(), failure::Error>;

    /// Finalize a transfer from FastPay to Libra.
    fn handle_redeem_transaction(
        &mut self,
        transaction: RedeemTransaction,
    ) -> Result<(), failure::Error>;
}
// -- END FILE --

impl FastPaySmartContract for FastPaySmartContractState {
    // -- BEGIN FILE fastpay_smart_contract_impl --
    /// Initiate a transfer to FastPay.
    fn handle_funding_transaction(
        &mut self,
        transaction: FundingTransaction,
    ) -> Result<(), failure::Error> {
        // TODO: Authentication by Libra sender
        let amount = transaction.libra_coins;
        ensure!(
            amount > Amount::zero(),
            "Transfers must have positive amount",
        );
        // TODO: Make sure that under overflow/underflow we are consistent.
        self.last_transaction_index = self.last_transaction_index.increment()?;
        self.blockchain.push(transaction);
        self.total_balance = self.total_balance.add(amount)?;
        Ok(())
    }

    /// Finalize a transfer from FastPay.
    fn handle_redeem_transaction(
        &mut self,
        transaction: RedeemTransaction,
    ) -> Result<(), failure::Error> {
        transaction.transfer_certificate.check(&self.committee)?;
        let order = transaction.transfer_certificate.value;
        let transfer = &order.transfer;
        ensure!(
            self.total_balance >= transfer.amount,
            "The balance on the blockchain cannot be negative",
        );
        let account = self
            .accounts
            .entry(transfer.sender)
            .or_insert(AccountOnchainState::new());
        ensure!(
            account.last_redeemed < Some(transfer.sequence_number),
            "Transfer certificates to Libra must have increasing sequence numbers.",
        );
        account.last_redeemed = Some(transfer.sequence_number);
        self.total_balance = self.total_balance.sub(transfer.amount)?;
        // Transfer Libra coins to order.recipient

        Ok(())
    }
    // -- END FILE --
}

impl AccountOnchainState {
    fn new() -> Self {
        Self {
            last_redeemed: None,
        }
    }
}

impl FastPaySmartContractState {
    pub fn new(committee: Committee) -> Self {
        FastPaySmartContractState {
            committee,
            total_balance: Amount::zero(),
            last_transaction_index: VersionNumber::new(),
            blockchain: Vec::new(),
            accounts: BTreeMap::new(),
        }
    }
}
