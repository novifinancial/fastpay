use crate::connection::Connection;
use crate::error::NetworkError;
use bytes::Bytes;
use fastpay_core::{
    base_types::*,
    committee::Committee,
    messages::*,
    serialize::{
        deserialize_message, serialize_confirmation_order, serialize_request_order,
        SerializedMessage,
    },
};
use futures::future::join_all;
use log::{info, warn};
use rand::Rng;
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    sync::mpsc::channel,
    time::{interval, sleep, Duration, Instant},
};

/// A client only useful to benchmark the authorities. It communicates with a single shard.
pub struct BenchmarkClient {
    /// The network addresses of the target shard (one per authority) where to submit requests.
    targets: Vec<SocketAddr>,
    /// The committee information.
    committee: Committee,
    /// The network addresses that must be reachable before starting the benchmark.
    /// TODO: Deduce these addresses from the committee.
    others: Vec<SocketAddr>,
    /// The number of requests per second that this client submits.
    rate: u64,
    /// A random keypair to generate the requests.
    keypair: KeyPair,
    /// A random integer ensuring every client (in case there are many) submit different requests.
    r: u64,
}

impl BenchmarkClient {
    /// Creates a new benchmark client.
    pub fn new(
        targets: Vec<SocketAddr>,
        committee: Committee,
        others: Vec<SocketAddr>,
        rate: u64,
    ) -> Self {
        Self {
            targets,
            committee,
            others,
            rate,
            keypair: KeyPair::generate(),
            r: rand::thread_rng().gen(),
        }
    }

    /// Log the benchmark parameters required to compute performance.
    pub fn print_parameters(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Transactions rate: {} tx/s", self.rate);
        for target in &self.targets {
            info!("Target shard address: {}", target);
        }
    }

    /// Wait for all authorities to be online.
    pub async fn wait(&self) {
        info!("Waiting for all authorities to be online...");
        join_all(self.others.iter().cloned().map(|address| {
            tokio::spawn(async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }))
        .await;
    }

    /// Run the benchmark.
    pub async fn benchmark(&self) -> Result<(), NetworkError> {
        const PRECISION: u64 = 20; // Timing burst precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;
        let burst = self.rate / PRECISION;
        let mut counter = 0; // Identifies sample transactions.

        // Connect to the mempool.
        let (tx_certificate, mut rx_certificate) = channel(1_000);
        let connection_handlers: Vec<_> = self
            .targets
            .iter()
            .map(|target| {
                let (tx_request, rx_request) = channel(1_000);
                Connection::spawn(*target, rx_request, tx_certificate.clone());
                tx_request
            })
            .collect();

        // Keeps track of votes to assemble certificates.
        let mut aggregators = HashMap::new();

        // Submit all transactions.
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        loop {
            tokio::select! {
                // Send a burst of request orders every 'tick'.
                _ = interval.tick() => {
                    let now = Instant::now();
                    for x in 0..burst {
                        let bytes = self.make_request(x, counter, burst);
                        for handler in &connection_handlers {
                            handler
                                .send(bytes.clone())
                                .await
                                .map_err(|_| NetworkError::ConnectionDropped)?;
                        }
                    }
                    counter += 1;

                    if now.elapsed().as_millis() > BURST_DURATION as u128 {
                        // NOTE: This log entry is used to compute performance.
                        warn!("Transaction rate too high for this client");
                    }
                },

                // Aggregate votes into certificates and re-broadcast them as soon as possible.
                Some(bytes) = rx_certificate.recv() => match deserialize_message(&*bytes)? {
                    SerializedMessage::InfoResponse(response) => {
                        if let Some(bytes) = self.try_make_certificate(response, &mut aggregators)? {
                            for handler in &connection_handlers {
                                handler
                                    .send(bytes.clone())
                                    .await
                                    .map_err(|_| NetworkError::ConnectionDropped)?;
                            }
                        }
                    },
                    SerializedMessage::Error(e) => Err(NetworkError::SerializationError(e.to_string()))?,
                    reply @ _ => Err(NetworkError::UnexpectedReply(reply))?
                }
            }
        }
    }

    /// Make a dummy (but valid) request order.
    fn make_request(&self, x: u64, counter: u64, burst: u64) -> Bytes {
        // Create the sender and receiver ensuring they don't clash.
        let sender = AccountId::new(vec![
            SequenceNumber::new(),
            SequenceNumber::from(x),
            SequenceNumber::from(self.r + counter),
        ]);
        let recipient = AccountId::new(vec![
            SequenceNumber::from(self.r + counter),
            SequenceNumber::from(x),
            SequenceNumber::new(),
        ]);

        // We will use the user-data to distinguish sample transactions.
        let user_data = (x == counter % burst).then(|| {
            let mut data = [0u8; 32];
            data[..8].clone_from_slice(&counter.to_le_bytes());
            data
        });

        // Make a transfer request for 1 coin.
        let request = Request {
            account_id: sender,
            operation: Operation::Transfer {
                recipient: Address::FastPay(recipient),
                amount: Amount::from(1),
                user_data: UserData(user_data.clone()),
            },
            sequence_number: SequenceNumber::new(),
        };
        let order = RequestOrder::new(request.into(), &self.keypair, Vec::new());
        let serialized_order = serialize_request_order(&order);

        if user_data.is_some() {
            // NOTE: This log entry is used to compute performance.
            info!("Sending sample transaction {}", counter);
        }

        Bytes::from(serialized_order)
    }

    // Try to assemble a certificate from votes.
    fn try_make_certificate<'a>(
        &'a self,
        response: Box<AccountInfoResponse>,
        aggregators: &mut HashMap<AccountId, SignatureAggregator<'a>>,
    ) -> Result<Option<Bytes>, NetworkError> {
        warn!("{:?}", response);
        let vote = response
            .pending
            .ok_or_else(|| NetworkError::ResponseWithoutVote)?;

        aggregators
            .entry(response.account_id.clone())
            .or_insert_with(|| SignatureAggregator::new(vote.value.clone(), &self.committee))
            .append(vote.authority, vote.signature)?
            .map_or(Ok(None), |certificate| {
                // NOTE: This log entry is used to compute performance.
                info!(
                    "Assembled certificate {:?}",
                    certificate
                        .value
                        .confirm_account_id()
                        .unwrap()
                        .sequence_number()
                        .unwrap()
                        .0
                );

                let serialized = serialize_confirmation_order(&ConfirmationOrder { certificate });
                Ok(Some(Bytes::from(serialized)))
            })
    }
}
