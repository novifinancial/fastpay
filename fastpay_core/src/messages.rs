// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{base_types::*, committee::Committee, error::*};

#[cfg(test)]
#[path = "unit_tests/messages_tests.rs"]
mod messages_tests;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct FundingTransaction {
    pub recipient: AccountId,
    pub primary_coins: Amount,
    // TODO: Authenticated by Primary sender.
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct PrimarySynchronizationOrder {
    pub recipient: AccountId,
    pub amount: Amount,
    pub transaction_index: VersionNumber,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Address {
    Primary(PrimaryAddress),
    FastPay(AccountId),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Operation {
    Transfer {
        recipient: Address,
        amount: Amount,
        user_data: UserData,
    },
    OpenAccount {
        new_id: AccountId,
        new_owner: AccountOwner,
    },
    CloseAccount,
    ChangeOwner {
        new_owner: AccountOwner,
    },
    Spend {
        account_balance: Amount,
        contract_hash: HashValue,
    },
    SpendAndTransfer {
        recipient: Address,
        amount: Amount,
    },
}

impl Operation {
    pub fn recipient(&self) -> Option<&AccountId> {
        use Operation::*;
        match self {
            Transfer {
                recipient: Address::FastPay(id),
                ..
            }
            | Operation::SpendAndTransfer {
                recipient: Address::FastPay(id),
                ..
            }
            | OpenAccount { new_id: id, .. } => Some(id),

            Operation::Spend { .. }
            | Operation::SpendAndTransfer { .. }
            | Operation::CloseAccount
            | Transfer { .. }
            | ChangeOwner { .. } => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Request {
    pub account_id: AccountId,
    pub operation: Operation,
    pub sequence_number: SequenceNumber,
}

// TODO: This could be an enum to allow several types of coins.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub account_id: AccountId,
    pub amount: Amount,
}

// TODO: decide if we split Vote & Certificate in one type per kind of value.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Value {
    Lock(Request),
    Confirm(Request),
    Coin(Coin),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RequestOrder {
    pub request: Request,
    pub owner: AccountOwner,
    pub signature: Signature,
    pub assets: Vec<Certificate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationSource {
    pub account_id: AccountId,
    pub amount: Amount,
    pub coins: Vec<Certificate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationContract {
    pub seed: u128, // make sure hash(contract) cannot be guessed
    pub sources: Vec<CoinCreationSource>,
    pub targets: Vec<Coin>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationOrder {
    pub contract: CoinCreationContract,
    pub locks: Vec<Certificate>, // Spend operation with amounts and hashes matching the sources.
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Vote {
    pub value: Value,
    pub authority: AuthorityName,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Certificate {
    pub value: Value,
    pub signatures: Vec<(AuthorityName, Signature)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RedeemTransaction {
    pub certificate: Certificate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct ConfirmationOrder {
    pub certificate: Certificate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AccountInfoQuery {
    pub account_id: AccountId,
    pub query_sequence_number: Option<SequenceNumber>,
    pub query_received_requests_excluding_first_nth: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AccountInfoResponse {
    pub account_id: AccountId,
    pub owner: Option<AccountOwner>,
    pub balance: Balance,
    pub next_sequence_number: SequenceNumber,
    pub pending: Option<Vote>,
    pub queried_certificate: Option<Certificate>,
    pub queried_received_requests: Vec<Certificate>,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ConfirmationOutcome {
    Complete,
    Retry,
    Cancel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum CrossShardRequest {
    UpdateRecipient { certificate: Certificate },
    DestroyAccount { account_id: AccountId },
}

impl Value {
    pub fn confirm_account_id(&self) -> Option<&AccountId> {
        match self {
            Value::Confirm(r) => Some(&r.account_id),
            _ => None,
        }
    }

    pub fn confirm_sequence_number(&self) -> Option<SequenceNumber> {
        match self {
            Value::Confirm(r) => Some(r.sequence_number),
            _ => None,
        }
    }

    pub fn confirm_request(&self) -> Option<&Request> {
        match self {
            Value::Confirm(r) => Some(r),
            Value::Coin(_) | Value::Lock(_) => None,
        }
    }

    #[cfg(test)]
    pub fn confirm_request_mut(&mut self) -> Option<&mut Request> {
        match self {
            Value::Confirm(r) => Some(r),
            Value::Coin(_) | Value::Lock(_) => None,
        }
    }

    pub fn confirm_key(&self) -> Option<(AccountId, SequenceNumber)> {
        match self {
            Value::Confirm(r) => Some((r.account_id.clone(), r.sequence_number)),
            Value::Coin(_) | Value::Lock(_) => None,
        }
    }
}

/// Non-testing code should make the pattern matching explicit so that
/// we kwow where to add protocols in the future.
#[cfg(test)]
impl Request {
    pub(crate) fn amount(&self) -> Option<Amount> {
        match &self.operation {
            Operation::Transfer { amount, .. } => Some(*amount),
            _ => None,
        }
    }

    pub(crate) fn amount_mut(&mut self) -> Option<&mut Amount> {
        match &mut self.operation {
            Operation::Transfer { amount, .. } => Some(amount),
            _ => None,
        }
    }
}

impl RequestOrder {
    pub fn new(request: Request, secret: &KeyPair, assets: Vec<Certificate>) -> Self {
        let signature = Signature::new(&request, secret);
        Self {
            request,
            owner: secret.public(),
            signature,
            assets,
        }
    }

    pub fn check(&self, authentication_method: &Option<AccountOwner>) -> Result<(), FastPayError> {
        fp_ensure!(
            authentication_method == &Some(self.owner),
            FastPayError::InvalidOwner
        );
        self.signature.check(&self.request, self.owner)
    }
}

impl Vote {
    /// Use signing key to create a signed object.
    pub fn new(value: Value, key_pair: &KeyPair) -> Self {
        let signature = Signature::new(&value, key_pair);
        Self {
            value,
            authority: key_pair.public(),
            signature,
        }
    }

    /// Verify the signature and return the non-zero voting right of the authority.
    pub fn check(&self, committee: &Committee) -> Result<usize, FastPayError> {
        let weight = committee.weight(&self.authority);
        fp_ensure!(weight > 0, FastPayError::UnknownSigner);
        self.signature.check(&self.value, self.authority)?;
        Ok(weight)
    }
}

pub struct SignatureAggregator<'a> {
    committee: &'a Committee,
    weight: usize,
    used_authorities: HashSet<AuthorityName>,
    partial: Certificate,
}

impl<'a> SignatureAggregator<'a> {
    /// Start aggregating signatures for the given value into a certificate.
    pub fn new(value: Value, committee: &'a Committee) -> Self {
        Self {
            committee,
            weight: 0,
            used_authorities: HashSet::new(),
            partial: Certificate {
                value,
                signatures: Vec::new(),
            },
        }
    }

    /// Try to append a signature to a (partial) certificate. Returns Some(certificate) if a quorum was reached.
    /// The resulting final certificate is guaranteed to be valid in the sense of `check` below.
    /// Returns an error if the signed value cannot be aggregated.
    pub fn append(
        &mut self,
        authority: AuthorityName,
        signature: Signature,
    ) -> Result<Option<Certificate>, FastPayError> {
        signature.check(&self.partial.value, authority)?;
        // Check that each authority only appears once.
        fp_ensure!(
            !self.used_authorities.contains(&authority),
            FastPayError::CertificateAuthorityReuse
        );
        self.used_authorities.insert(authority);
        // Update weight.
        let voting_rights = self.committee.weight(&authority);
        fp_ensure!(voting_rights > 0, FastPayError::UnknownSigner);
        self.weight += voting_rights;
        // Update certificate.
        self.partial.signatures.push((authority, signature));

        if self.weight >= self.committee.quorum_threshold() {
            Ok(Some(self.partial.clone()))
        } else {
            Ok(None)
        }
    }
}

impl Certificate {
    /// Verify the certificate.
    pub fn check(&self, committee: &Committee) -> Result<(), FastPayError> {
        // Check the quorum.
        let mut weight = 0;
        let mut used_authorities = HashSet::new();
        for (authority, _) in self.signatures.iter() {
            // Check that each authority only appears once.
            fp_ensure!(
                !used_authorities.contains(authority),
                FastPayError::CertificateAuthorityReuse
            );
            used_authorities.insert(*authority);
            // Update weight.
            let voting_rights = committee.weight(authority);
            fp_ensure!(voting_rights > 0, FastPayError::UnknownSigner);
            weight += voting_rights;
        }
        fp_ensure!(
            weight >= committee.quorum_threshold(),
            FastPayError::CertificateRequiresQuorum
        );
        // All what is left is checking signatures!
        Signature::verify_batch(&self.value, &self.signatures)
    }
}

impl RedeemTransaction {
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }
}

impl ConfirmationOrder {
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }
}

impl BcsSignable for Request {}
impl BcsSignable for Value {}
impl BcsSignable for CoinCreationContract {}
