use crate::error::BenchError;
use bytes::Bytes;
use fastpay_core::{
    base_types::{AccountId, Amount, KeyPair, SequenceNumber, UserData},
    committee::Committee,
    messages::{
        AccountInfoResponse, Address, ConfirmationOrder, Operation, Request, RequestOrder,
        SignatureAggregator,
    },
    serialize::{serialize_confirmation_order, serialize_request_order},
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
    pub fn make_request(&self, x: u64, counter: u64, burst: u64) -> Bytes {
        let sample = match x == counter % burst {
            true => counter,
            false => 0,
        };

        // Create the sender and receiver ensuring they don't clash.
        let sender = AccountId::new(vec![
            SequenceNumber::from(sample),
            SequenceNumber::from(x),
            SequenceNumber::from(self.r + counter),
        ]);
        let recipient = AccountId::new(vec![
            SequenceNumber::from(self.r + counter),
            SequenceNumber::from(x),
            SequenceNumber::new(),
        ]);

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
        Bytes::from(serialized_order)
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
        let vote = response
            .pending
            .ok_or_else(|| BenchError::ResponseWithoutVote)?;

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