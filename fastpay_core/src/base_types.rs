// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek as dalek;
use ed25519_dalek::{Signer, Verifier};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use crate::error::FastPayError;

#[cfg(test)]
#[path = "unit_tests/base_types_tests.rs"]
mod base_types_tests;

#[derive(
    Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Default, Debug, Serialize, Deserialize,
)]
pub struct Amount(u64);
#[derive(
    Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Default, Debug, Serialize, Deserialize,
)]
pub struct Balance(i128);
#[derive(
    Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Default, Debug, Serialize, Deserialize,
)]
pub struct SequenceNumber(u64);

pub type ShardId = u32;
pub type VersionNumber = SequenceNumber;

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Hash, Default, Debug, Serialize, Deserialize)]
pub struct UserData(pub Option<[u8; 32]>);

// TODO: Make sure secrets are not copyable and movable to control where they are in memory
pub struct KeyPair(dalek::Keypair);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash)]
pub struct PublicKeyBytes(pub [u8; dalek::PUBLIC_KEY_LENGTH]);

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Hash, Serialize, Deserialize)]
pub struct AccountId(Vec<SequenceNumber>);

pub type PrimaryAddress = PublicKeyBytes;
pub type AuthorityName = PublicKeyBytes;
pub type AccountOwner = PublicKeyBytes;

pub fn get_key_pair() -> KeyPair {
    let mut csprng = OsRng;
    let keypair = dalek::Keypair::generate(&mut csprng);
    KeyPair(keypair)
}

#[cfg(test)]
pub fn dbg_account(name: u8) -> AccountId {
    AccountId(vec![SequenceNumber(name.into())])
}

#[cfg(test)]
pub fn dbg_addr(name: u8) -> PublicKeyBytes {
    let addr = [name; dalek::PUBLIC_KEY_LENGTH];
    PublicKeyBytes(addr)
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct Signature(dalek::Signature);

impl KeyPair {
    pub fn public(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.0.public.to_bytes())
    }

    /// Avoid implementing `clone` on secret keys to prevent mistakes.
    pub fn copy(&self) -> KeyPair {
        KeyPair(dalek::Keypair {
            secret: dalek::SecretKey::from_bytes(self.0.secret.as_bytes()).unwrap(),
            public: dalek::PublicKey::from_bytes(self.0.public.as_bytes()).unwrap(),
        })
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_newtype_struct("PublicKeyBytes", &self.0)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let value =
                Self::from_str(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
            Ok(value)
        } else {
            #[derive(Deserialize)]
            #[serde(rename = "PublicKeyBytes")]
            struct Foo([u8; dalek::PUBLIC_KEY_LENGTH]);

            let value = Foo::deserialize(deserializer)?;
            Ok(Self(value.0))
        }
    }
}

impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // This is only used for JSON configuration.
        assert!(serializer.is_human_readable());
        serializer.serialize_str(&hex::encode(&self.0.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        // This is only used for JSON configuration.
        assert!(deserializer.is_human_readable());
        let s = String::deserialize(deserializer)?;
        let value = hex::decode(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
        let key = dalek::Keypair::from_bytes(&value)
            .map_err(|err| serde::de::Error::custom(err.to_string()))?;
        Ok(KeyPair(key))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&self.0.to_bytes()))
        } else {
            serializer.serialize_newtype_struct("Signature", &self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            use ed25519_dalek::ed25519::signature::Signature;

            let s = String::deserialize(deserializer)?;
            let value = hex::decode(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
            let sig = dalek::Signature::from_bytes(&value)
                .map_err(|err| serde::de::Error::custom(err.to_string()))?;
            Ok(Signature(sig))
        } else {
            #[derive(Deserialize)]
            #[serde(rename = "Signature")]
            struct Foo(dalek::Signature);

            let value = Foo::deserialize(deserializer)?;
            Ok(Self(value.0))
        }
    }
}

impl std::fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}

impl FromStr for PublicKeyBytes {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = hex::decode(s)?;
        if value.len() != dalek::PUBLIC_KEY_LENGTH {
            failure::bail!("Invalid length for hex-encoded public key");
        }
        let mut pubkey = [0u8; dalek::PUBLIC_KEY_LENGTH];
        pubkey.copy_from_slice(&value[..dalek::PUBLIC_KEY_LENGTH]);
        Ok(PublicKeyBytes(pubkey))
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self.0).unwrap())
    }
}

impl FromStr for AccountId {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AccountId(serde_json::from_str(s)?))
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let s = hex::encode(&self.0.to_bytes());
        write!(f, "{}", s)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self)
    }
}

impl std::fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self)
    }
}

impl std::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}", self)
    }
}

impl AccountId {
    pub fn new(numbers: Vec<SequenceNumber>) -> Self {
        assert!(!numbers.is_empty());
        Self(numbers)
    }

    pub fn parent(&self) -> Option<AccountId> {
        if self.0.len() <= 1 {
            return None;
        }
        let mut parent = self.clone();
        parent.0.pop()?;
        Some(parent)
    }

    pub fn sequence_number(&self) -> Option<SequenceNumber> {
        self.0.last().cloned()
    }

    pub fn make_child(&self, num: SequenceNumber) -> Self {
        let mut id = self.clone();
        id.0.push(num);
        id
    }
}

impl Amount {
    pub fn zero() -> Self {
        Amount(0)
    }

    pub fn try_add(self, other: Self) -> Result<Self, FastPayError> {
        let val = self.0.checked_add(other.0);
        match val {
            None => Err(FastPayError::AmountOverflow),
            Some(val) => Ok(Self(val)),
        }
    }

    pub fn try_sub(self, other: Self) -> Result<Self, FastPayError> {
        let val = self.0.checked_sub(other.0);
        match val {
            None => Err(FastPayError::AmountUnderflow),
            Some(val) => Ok(Self(val)),
        }
    }
}

impl Balance {
    pub fn zero() -> Self {
        Balance(0)
    }

    pub fn max() -> Self {
        Balance(std::i128::MAX)
    }

    pub fn try_add(&self, other: Self) -> Result<Self, FastPayError> {
        let val = self.0.checked_add(other.0);
        match val {
            None => Err(FastPayError::BalanceOverflow),
            Some(val) => Ok(Self(val)),
        }
    }

    pub fn try_sub(&self, other: Self) -> Result<Self, FastPayError> {
        let val = self.0.checked_sub(other.0);
        match val {
            None => Err(FastPayError::BalanceUnderflow),
            Some(val) => Ok(Self(val)),
        }
    }
}

impl std::fmt::Display for Balance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for Balance {
    type Err = std::num::ParseIntError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Ok(Self(i128::from_str(src)?))
    }
}

impl From<Amount> for u64 {
    fn from(val: Amount) -> Self {
        val.0
    }
}

impl From<Amount> for Balance {
    fn from(val: Amount) -> Self {
        Balance(val.0 as i128)
    }
}

impl TryFrom<Balance> for Amount {
    type Error = std::num::TryFromIntError;

    fn try_from(val: Balance) -> Result<Self, Self::Error> {
        Ok(Amount(val.0.try_into()?))
    }
}

impl SequenceNumber {
    pub fn new() -> Self {
        SequenceNumber(0)
    }

    pub fn max() -> Self {
        SequenceNumber(0x7fff_ffff_ffff_ffff)
    }

    pub fn increment(self) -> Result<SequenceNumber, FastPayError> {
        let val = self.0.checked_add(1);
        match val {
            None => Err(FastPayError::SequenceOverflow),
            Some(val) => Ok(Self(val)),
        }
    }

    pub fn decrement(self) -> Result<SequenceNumber, FastPayError> {
        let val = self.0.checked_sub(1);
        match val {
            None => Err(FastPayError::SequenceUnderflow),
            Some(val) => Ok(Self(val)),
        }
    }
}

impl From<SequenceNumber> for u64 {
    fn from(val: SequenceNumber) -> Self {
        val.0
    }
}

impl From<u64> for Amount {
    fn from(value: u64) -> Self {
        Amount(value)
    }
}

impl From<i128> for Balance {
    fn from(value: i128) -> Self {
        Balance(value)
    }
}

impl From<u64> for SequenceNumber {
    fn from(value: u64) -> Self {
        SequenceNumber(value)
    }
}

impl From<SequenceNumber> for usize {
    fn from(value: SequenceNumber) -> Self {
        value.0 as usize
    }
}

/// Something that we know how to hash and sign.
pub trait Signable<Hasher> {
    fn write(&self, hasher: &mut Hasher);
}

/// Activate the blanket implementation of `Signable` based on serde and BCS.
/// * We use `serde_name` to extract a seed from the name of structs and enums.
/// * We use `BCS` to generate canonical bytes suitable for hashing and signing.
pub trait BcsSignable: Serialize + serde::de::DeserializeOwned {}

impl<T, Hasher> Signable<Hasher> for T
where
    T: BcsSignable,
    Hasher: std::io::Write,
{
    fn write(&self, hasher: &mut Hasher) {
        let name = serde_name::trace_name::<Self>().expect("Self must be a struct or an enum");
        // Note: This assumes that names never contain the separator `::`.
        write!(hasher, "{}::", name).expect("Hasher should not fail");
        bcs::serialize_into(hasher, &self).expect("Message serialization should not fail");
    }
}

impl Signature {
    pub fn new<T>(value: &T, secret: &KeyPair) -> Self
    where
        T: Signable<Vec<u8>>,
    {
        let mut message = Vec::new();
        value.write(&mut message);
        let signature = secret.0.sign(&message);
        Signature(signature)
    }

    fn check_internal<T>(
        &self,
        value: &T,
        author: PublicKeyBytes,
    ) -> Result<(), dalek::SignatureError>
    where
        T: Signable<Vec<u8>>,
    {
        let mut message = Vec::new();
        value.write(&mut message);
        let public_key = dalek::PublicKey::from_bytes(&author.0)?;
        public_key.verify(&message, &self.0)
    }

    pub fn check<T>(&self, value: &T, author: PublicKeyBytes) -> Result<(), FastPayError>
    where
        T: Signable<Vec<u8>>,
    {
        self.check_internal(value, author)
            .map_err(|error| FastPayError::InvalidSignature {
                error: format!("{}", error),
            })
    }

    fn verify_batch_internal<'a, T, I>(value: &'a T, votes: I) -> Result<(), dalek::SignatureError>
    where
        T: Signable<Vec<u8>>,
        I: IntoIterator<Item = &'a (PublicKeyBytes, Signature)>,
    {
        let mut msg = Vec::new();
        value.write(&mut msg);
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut public_keys: Vec<dalek::PublicKey> = Vec::new();
        for (addr, sig) in votes.into_iter() {
            messages.push(&msg);
            signatures.push(sig.0);
            public_keys.push(dalek::PublicKey::from_bytes(&addr.0)?);
        }
        dalek::verify_batch(&messages[..], &signatures[..], &public_keys[..])
    }

    pub fn verify_batch<'a, T, I>(value: &'a T, votes: I) -> Result<(), FastPayError>
    where
        T: Signable<Vec<u8>>,
        I: IntoIterator<Item = &'a (PublicKeyBytes, Signature)>,
    {
        Signature::verify_batch_internal(value, votes).map_err(|error| {
            FastPayError::InvalidSignature {
                error: format!("{}", error),
            }
        })
    }
}
