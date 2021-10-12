// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{base_types::*, committee::Committee, error::FastPayError};

#[cfg(test)]
#[path = "unit_tests/messages_tests.rs"]
mod messages_tests;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A message sent from the smart contract on the primary chain.
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct PrimarySynchronizationOrder {
    pub recipient: AccountId,
    pub amount: Amount,
    pub transaction_index: SequenceNumber,
}

/// A recipient's address in FastPay or on the primary chain.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Address {
    Primary(PrimaryAddress),
    FastPay(AccountId),
}

/// An account operation in FastPay.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Operation {
    /// Transfer `amount` units of value to the recipient.
    Transfer {
        recipient: Address,
        amount: Amount,
        user_data: UserData,
    },
    /// Create (or activate) a new account by installing the given authentication key.
    OpenAccount {
        new_id: AccountId,
        new_owner: AccountOwner,
    },
    /// Close the account.
    CloseAccount,
    /// Change the authentication key of the account.
    ChangeOwner { new_owner: AccountOwner },
    /// Lock the account so that the balance and linked coins may be eventually transfered
    /// to new coins (according to the "coin creation description" behind `description_hash`).
    Spend {
        account_balance: Amount,
        description_hash: HashValue,
    },
    /// Close the account (and spend a number of linked coins) to transfer the given total
    /// amount to the recipient.
    SpendAndTransfer {
        recipient: Address,
        amount: Amount,
        user_data: UserData,
    },
}

/// A request containing an account operation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Request {
    pub account_id: AccountId,
    pub operation: Operation,
    pub sequence_number: SequenceNumber,
}

/// The content of a request to be signed in a RequestOrder.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct RequestValue {
    pub request: Request,
    pub limited_to: Option<AuthorityName>,
}

/// An authenticated request plus additional certified assets.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RequestOrder {
    pub value: RequestValue,
    pub owner: AccountOwner,
    pub signature: Signature,
    pub assets: Vec<Certificate>,
}

/// A transparent coin linked a given account.
// TODO: This could be an enum to allow several types of coins.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub account_id: AccountId,
    pub amount: Amount,
    pub seed: u128,
}

/// A statement to be certified by the authorities.
// TODO: decide if we split Vote & Certificate in one type per kind of value.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Value {
    Lock(Request),
    Confirm(Request),
    Coin(Coin),
}

/// The balance of an account plus linked coins to be used in a coin creation description.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationSource {
    pub account_id: AccountId,
    pub account_balance: Amount,
    pub coins: Vec<Certificate>,
}

/// Instructions to create a number of coins during a CoinCreationOrder.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationDescription {
    /// The sources to be used for coin creation.
    pub sources: Vec<CoinCreationSource>,
    /// The coins to be created.
    pub targets: Vec<Coin>,
}

/// Same as RequestOrder but meant to create coins.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationOrder {
    /// Instructions to create the coins.
    pub description: CoinCreationDescription,
    /// Proof that the source accounts have been locked with a suitable "Spend" operation
    /// and the account balances are correct.
    pub locks: Vec<Certificate>,
}

/// A vote on a statement from an authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Vote {
    pub value: Value,
    pub authority: AuthorityName,
    pub signature: Signature,
}

/// A certified statement from the committee.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Certificate {
    pub value: Value,
    pub signatures: Vec<(AuthorityName, Signature)>,
}

/// Order to process a confirmed request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct ConfirmationOrder {
    pub certificate: Certificate,
}

/// Message to obtain information on an account.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AccountInfoQuery {
    pub account_id: AccountId,
    pub query_sequence_number: Option<SequenceNumber>,
    pub query_received_certificates_excluding_first_nth: Option<usize>,
}

/// The response to an `AccountInfoQuery`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AccountInfoResponse {
    pub account_id: AccountId,
    pub owner: Option<AccountOwner>,
    pub balance: Balance,
    pub next_sequence_number: SequenceNumber,
    pub pending: Option<Vote>,
    pub count_received_certificates: usize,
    pub queried_certificate: Option<Certificate>,
    pub queried_received_certificates: Vec<Certificate>,
}

/// A (trusted) cross-shard request with an authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum CrossShardRequest {
    UpdateRecipient { certificate: Certificate },
    DestroyAccount { account_id: AccountId },
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

    pub fn received_amount(&self) -> Option<Amount> {
        use Operation::*;
        match self {
            Transfer { amount, .. } | Operation::SpendAndTransfer { amount, .. } => Some(*amount),
            _ => None,
        }
    }
}

impl Value {
    pub fn coin_amount(&self) -> Option<Amount> {
        match self {
            Value::Coin(coin) => Some(coin.amount),
            _ => None,
        }
    }

    pub fn coin_account_id(&self) -> Option<&AccountId> {
        match self {
            Value::Coin(coin) => Some(&coin.account_id),
            _ => None,
        }
    }

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
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn confirm_request_mut(&mut self) -> Option<&mut Request> {
        match self {
            Value::Confirm(r) => Some(r),
            _ => None,
        }
    }

    pub fn confirm_key(&self) -> Option<(AccountId, SequenceNumber)> {
        match self {
            Value::Confirm(r) => Some((r.account_id.clone(), r.sequence_number)),
            _ => None,
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

impl From<Request> for RequestValue {
    fn from(request: Request) -> Self {
        Self {
            request,
            limited_to: None,
        }
    }
}

impl RequestOrder {
    pub fn new(value: RequestValue, secret: &KeyPair, assets: Vec<Certificate>) -> Self {
        let signature = Signature::new(&value, secret);
        Self {
            value,
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
        self.signature.check(&self.value, self.owner)
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
    pub fn check<'a>(&'a self, committee: &Committee) -> Result<&'a Value, FastPayError> {
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
        Signature::verify_batch(&self.value, &self.signatures)?;
        Ok(&self.value)
    }
}

impl ConfirmationOrder {
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }
}

impl BcsSignable for RequestValue {}
impl BcsSignable for Value {}
impl BcsSignable for CoinCreationDescription {}
