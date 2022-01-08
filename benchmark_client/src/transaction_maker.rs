// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::error::BenchError;
use bytes::Bytes;
use fastpay_core::{
    base_types::{AccountId, Amount, HashValue, KeyPair, SequenceNumber, UserData},
    committee::Committee,
    messages::{
        AccountInfoResponse, Address, CoinCreationDescription, CoinCreationOrder,
        CoinCreationSource, ConfirmationOrder, OpaqueCoin, Operation, Request, RequestOrder,
        SignatureAggregator,
    },
    serialize::{
        serialize_coin_creation_order, serialize_confirmation_order, serialize_request_order,
    },
};
use rand::Rng;
use std::collections::HashMap;

/// Creates dumb (but valid) requests.
pub struct DumbRequestMaker {
    /// A random keypair to generate the requests.
    keypair: KeyPair,
    /// A random integer ensuring every client (in case there are many) submit different requests.
    r: u64,
}

impl DumbRequestMaker {
    pub fn new() -> Self {
        Self {
            keypair: KeyPair::generate(),
            r: rand::thread_rng().gen(),
        }
    }

    /// Make a dummy (but valid) request order.
    pub fn make_request(&self, x: u64, counter: u64, burst: u64) -> (Bytes, u64) {
        // Create the sender and receiver ensuring they don't clash.
        let id = self.r + counter * burst + x;
        let sender = AccountId::new(vec![SequenceNumber::new(), SequenceNumber::from(id)]);
        let recipient = AccountId::new(vec![SequenceNumber::from(id), SequenceNumber::new()]);

        // Make a transfer request for 1 coin.
        let request = Request {
            account_id: sender,
            operation: Operation::Transfer {
                recipient: Address::FastPay(recipient),
                amount: Amount::from(1),
                user_data: UserData::default(),
            },
            sequence_number: SequenceNumber::new(),
        };
        let order = RequestOrder::new(request.into(), &self.keypair, Vec::new());
        let serialized_order = serialize_request_order(&order);
        (Bytes::from(serialized_order), id)
    }
}

/// Creates dumb (but valid) certificates.
pub struct DumbCertificateMaker {
    /// The committee information.
    pub committee: Committee,
}

impl DumbCertificateMaker {
    /// Try to assemble a certificate from votes.
    pub fn try_make_certificate<'a>(
        &'a self,
        response: Box<AccountInfoResponse>,
        aggregators: &mut HashMap<AccountId, SignatureAggregator<'a>>,
    ) -> Result<Option<Bytes>, BenchError> {
        let vote = response.pending.ok_or(BenchError::ResponseWithoutVote)?;

        aggregators
            .entry(response.account_id.clone())
            .or_insert_with(|| SignatureAggregator::new(vote.value.clone(), &self.committee))
            .append(vote.authority, vote.signature)?
            .map_or(Ok(None), |certificate| {
                let serialized = serialize_confirmation_order(&ConfirmationOrder { certificate });
                Ok(Some(Bytes::from(serialized)))
            })
    }
}

pub fn make_coins(
    master_secret: &coconut::SecretKey,
    parameters: &coconut::Parameters,
    verification_key: &coconut::PublicKey,
) -> (CoinCreationDescription, HashValue) {
    // Make two coins to spend during the benchmark.
    let coin_attributes_1 = OpaqueCoin {
        account_id: AccountId::new(vec![SequenceNumber::from(10)]),
        public_seed: 1,
        private_seed: 101,
        amount: Amount::from(2),
    };
    let input_attribute_1 = coin_attributes_1.make_input_attribute();
    let output_attribute_1 = coin_attributes_1.make_output_attribute();
    let credential_1 = coconut::Coin::default(
        parameters,
        master_secret,
        &input_attribute_1.value,
        &input_attribute_1.seed,
        &input_attribute_1.key,
    );

    let coin_attributes_2 = OpaqueCoin {
        account_id: AccountId::new(vec![SequenceNumber::from(10)]),
        public_seed: 2,
        private_seed: 102,
        amount: Amount::from(2),
    };
    let input_attribute_2 = coin_attributes_2.make_input_attribute();
    let output_attribute_2 = coin_attributes_2.make_output_attribute();
    let credential_2 = coconut::Coin::default(
        parameters,
        master_secret,
        &input_attribute_2.value,
        &input_attribute_2.seed,
        &input_attribute_2.key,
    );

    let source = CoinCreationSource {
        // This field is overwritten upon sending the request to allow transactions tracking.
        account_id: AccountId::default(),
        account_balance: Amount::from(0),
        transparent_coins: Vec::default(),
        opaque_coin_public_seeds: vec![1, 2],
    };
    let request = coconut::CoinsRequest::new(
        coconut::rand::thread_rng(),
        parameters,
        verification_key,
        &vec![credential_1, credential_2],
        &[input_attribute_1, input_attribute_2],
        &vec![output_attribute_1, output_attribute_2],
    );
    let description = CoinCreationDescription {
        sources: vec![source],
        targets: Vec::default(),
        coconut_request: Some(request),
    };
    let description_hash = HashValue::new(&description);
    (description, description_hash)
}

/// Creates dumb (but valid) requests.
pub struct DumbCoinRequestMaker {
    description_hash: HashValue,
    /// A random keypair to generate the requests.
    keypair: KeyPair,
    /// A random integer ensuring every client (in case there are many) submit different requests.
    r: u64,
}

impl DumbCoinRequestMaker {
    pub fn new(description_hash: HashValue) -> Self {
        Self {
            description_hash,
            keypair: KeyPair::generate(),
            r: rand::thread_rng().gen(),
        }
    }

    /// Make a dummy (but valid) lock request.
    pub fn make_lock_request(&self, x: u64, counter: u64, burst: u64) -> (Bytes, u64) {
        let id = self.r + counter * burst + x;
        let account_id = AccountId::new(vec![SequenceNumber::from(id)]);
        let request = Request {
            account_id,
            operation: Operation::Spend {
                account_balance: Amount::from(0),
                description_hash: self.description_hash,
            },
            sequence_number: SequenceNumber::new(),
        };
        let order = RequestOrder::new(request.into(), &self.keypair, Vec::default());
        let serialized_order = serialize_request_order(&order);
        (Bytes::from(serialized_order), id)
    }
}

/// Creates dumb (but valid) certificates.
pub struct DumbLockCertificateMaker {
    /// The committee information.
    pub committee: Committee,
    /// The coin description locked in the certificate.
    pub description: CoinCreationDescription,
}

impl DumbLockCertificateMaker {
    /// Try to assemble a certificate from votes.
    pub fn try_make_certificate<'a>(
        &'a self,
        response: Box<AccountInfoResponse>,
        aggregators: &mut HashMap<AccountId, SignatureAggregator<'a>>,
    ) -> Result<Option<Bytes>, BenchError> {
        let vote = response.pending.ok_or(BenchError::ResponseWithoutVote)?;
        aggregators
            .entry(response.account_id.clone())
            .or_insert_with(|| SignatureAggregator::new(vote.value.clone(), &self.committee))
            .append(vote.authority, vote.signature)?
            .map_or(Ok(None), |certificate| {
                let account_id = certificate.value.lock_account_id().unwrap().clone();
                let source = self.description.sources[0].clone();
                let source = CoinCreationSource {
                    account_id,
                    ..source
                };
                let description = CoinCreationDescription {
                    sources: vec![source],
                    ..self.description.clone()
                };
                let confirmation = CoinCreationOrder {
                    description,
                    locks: vec![certificate],
                };
                let serialized = serialize_coin_creation_order(&confirmation);
                Ok(Some(Bytes::from(serialized)))
            })
    }

    pub fn try_assemble_coins(
        &self,
        tracking_id: AccountId,
        aggregators: &mut HashMap<AccountId, usize>,
    ) -> Option<AccountId> {
        let stake = aggregators.entry(tracking_id.clone()).or_insert_with(|| 0);
        *stake += 1;
        (stake >= &mut self.committee.quorum_threshold()).then(|| tracking_id)
    }
}
