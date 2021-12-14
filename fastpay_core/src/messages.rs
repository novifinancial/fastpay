// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::{base_types::*, committee::Committee, error::FastPayError};
use ff::Field;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[cfg(test)]
#[path = "unit_tests/messages_tests.rs"]
mod messages_tests;

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
    /// Lock the account so that the balance and linked coins may be eventually transferred
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

/// A certified asset that we own.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Asset {
    TransparentCoin {
        certificate: Certificate,
    },
    OpaqueCoin {
        value: OpaqueCoin,
        credential: coconut::Coin,
    },
}

/// The description of an opaque coin as seen by its owner (or creator).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct OpaqueCoin {
    /// The owner's account
    pub account_id: AccountId,
    /// Unique number to distinguish coins inside an account.
    pub public_seed: u128,
    /// Random seed to make sure that the value stay confidential after spending the coin.
    pub private_seed: u128,
    /// Value of the coin.
    pub amount: Amount,
}

/// An authenticated request plus additional certified assets.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct RequestOrder {
    pub value: RequestValue,
    pub owner: AccountOwner,
    pub signature: Signature,
    pub assets: Vec<Asset>,
}

/// The description of a transparent coin linked a given account.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TransparentCoin {
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
    Coin(TransparentCoin),
}

/// The balance of an account plus linked coins to be used in a coin creation description.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationSource {
    /// The account being spent
    pub account_id: AccountId,
    /// The recorded balance
    pub account_balance: Amount,
    /// Known transparent coins
    pub transparent_coins: Vec<Certificate>,
    /// Public seeds for the coins in the coconut creation request.
    pub opaque_coin_public_seeds: Vec<u128>,
}

/// Instructions to create a number of coins during a CoinCreationOrder.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationDescription {
    /// The sources to be used for coin creation.
    pub sources: Vec<CoinCreationSource>,
    /// Transparent coins to be created.
    pub targets: Vec<TransparentCoin>,
    /// Request to consume opaque coins and create new (blinded) ones under ZK, if needed.
    pub coconut_request: Option<coconut::CoinsRequest>,
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

/// The response to a CoinCreationOrder
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CoinCreationResponse {
    /// Votes to create transparent coins.
    pub votes: Vec<Vote>,
    /// Blinded shares to create opaque coins.
    pub blinded_coins: Option<coconut::BlindedCoins>,
}

/// A vote on a statement from an authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Vote {
    pub value: Value,
    pub authority: AuthorityName,
    pub signature: Signature,
}

/// A certified statement from the committee. Note: Opaque coins have no external
/// signatures and are authenticated at a lower level.
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

#[cfg(test)]
impl From<Certificate> for Asset {
    fn from(certificate: Certificate) -> Self {
        Self::TransparentCoin { certificate }
    }
}

/// The component of the "key" public attribute of an opaque coin.
#[derive(Serialize, Deserialize)]
pub(crate) struct CoconutKey {
    /// Owner account
    pub(crate) account_id: AccountId,
    /// Number used to differentiate coins in the account.
    pub(crate) public_seed: u128,
}

impl CoconutKey {
    pub(crate) fn scalar(&self) -> bls12_381::Scalar {
        let hash = HashValue::new(self);
        bls12_381::Scalar::from_bytes_wide(hash.as_bytes())
    }
}

impl OpaqueCoin {
    pub fn make_input_attribute(&self) -> coconut::InputAttribute {
        let key = CoconutKey {
            account_id: self.account_id.clone(),
            public_seed: self.public_seed,
        };
        let value = u64::from(self.amount);
        let seed = bls12_381::Scalar::from_raw([
            self.private_seed as u64,
            (self.private_seed >> 64) as u64,
            0,
            0,
        ]);
        coconut::InputAttribute {
            key: key.scalar(),
            value: value.into(),
            seed,
        }
    }

    pub fn make_output_attribute(&self) -> coconut::OutputAttribute {
        let coconut::InputAttribute { key, value, seed } = self.make_input_attribute();
        let mut rng = coconut::rand::thread_rng();
        let key_blinding_factor = bls12_381::Scalar::random(&mut rng);
        let value_blinding_factor = bls12_381::Scalar::random(&mut rng);
        let seed_blinding_factor = bls12_381::Scalar::random(&mut rng);
        coconut::OutputAttribute {
            key,
            key_blinding_factor,
            value,
            value_blinding_factor,
            seed,
            seed_blinding_factor,
        }
    }
}

impl Asset {
    pub fn account_id(&self) -> Result<&AccountId, FastPayError> {
        match self {
            Asset::TransparentCoin { certificate } => match &certificate.value {
                Value::Coin(coin) => Ok(&coin.account_id),
                _ => Err(FastPayError::InvalidAsset),
            },
            Asset::OpaqueCoin {
                value: OpaqueCoin { account_id, .. },
                ..
            } => Ok(account_id),
        }
    }

    pub fn value(&self) -> Result<Amount, FastPayError> {
        match self {
            Asset::TransparentCoin { certificate } => match &certificate.value {
                Value::Coin(coin) => Ok(coin.amount),
                _ => Err(FastPayError::InvalidAsset),
            },
            Asset::OpaqueCoin {
                value: OpaqueCoin { amount, .. },
                ..
            } => Ok(*amount),
        }
    }

    pub fn check(&self, committee: &Committee) -> Result<(), FastPayError> {
        match self {
            Asset::TransparentCoin { certificate } => {
                let value = certificate.check(committee)?;
                fp_ensure!(
                    matches!(value, Value::Coin { .. }),
                    FastPayError::InvalidAsset
                );
            }
            Asset::OpaqueCoin { value, credential } => {
                let setup = match &committee.coconut_setup {
                    Some(setup) => setup,
                    None => {
                        return Err(FastPayError::InvalidAsset);
                    }
                };
                let attribute = value.make_input_attribute();
                fp_ensure!(
                    credential.plain_verify(
                        &setup.parameters,
                        &setup.verification_key,
                        attribute.value,
                        attribute.seed,
                        attribute.key
                    ),
                    FastPayError::InvalidAsset
                );
            }
        }
        Ok(())
    }
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
/// we know where to add protocols in the future.
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
    pub fn new(value: RequestValue, secret: &KeyPair, assets: Vec<Asset>) -> Self {
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
impl BcsSignable for CoconutKey {}
impl BcsSignable for CoinCreationDescription {}
