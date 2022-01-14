// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    connection::Connection,
    error::BenchError,
    transaction_maker::{make_coins, DumbCoinRequestMaker, DumbLockCertificateMaker},
};
use bytes::Bytes;
use fastpay_core::{
    base_types::HashValue,
    committee::Committee,
    messages::{CoinCreationDescription, CoinCreationResponse},
    serialize::{deserialize_message, SerializedMessage},
};
use futures::future::{join_all, try_join};
use log::{debug, info, warn};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Receiver, Sender},
    task::JoinHandle,
    time::{interval, sleep, Duration, Instant},
};

/// The default channel capacity.
const CHANNEL_CAPACITY: usize = 1_000;

/// A client only useful to benchmark the authorities. It communicates with a single shard.
pub struct CocoBenchmarkClient {
    /// The network addresses of the target shard (one per authority) where to submit requests.
    targets: Vec<SocketAddr>,
    /// The committee information.
    committee: Committee,
    /// The network addresses that must be reachable before starting the benchmark.
    /// TODO: Deduce these addresses from the committee.
    others: Vec<SocketAddr>,
    /// The number of requests per second that this client submits.
    rate: u64,
    master_secret: coconut::SecretKey,
    coconut_parameters: coconut::Parameters,
    coconut_verification_key: coconut::PublicKey,
}

impl CocoBenchmarkClient {
    /// Creates a new benchmark client.
    pub fn new(
        targets: Vec<SocketAddr>,
        committee: Committee,
        others: Vec<SocketAddr>,
        rate: u64,
        master_secret: coconut::SecretKey,
        coconut_parameters: coconut::Parameters,
        coconut_verification_key: coconut::PublicKey,
    ) -> Self {
        Self {
            targets,
            committee,
            others,
            rate,
            master_secret,
            coconut_parameters,
            coconut_verification_key,
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

    /// Create a connection with all the targets.
    fn connect(&self, tx_response: Sender<Bytes>) -> Vec<Sender<Bytes>> {
        self.targets
            .iter()
            .map(|target| {
                let (tx_request, rx_request) = channel(CHANNEL_CAPACITY);
                Connection::spawn(*target, rx_request, tx_response.clone());
                tx_request
            })
            .collect()
    }

    fn send_requests(
        &self,
        tx_certificate: Sender<Bytes>,
        description_hash: HashValue,
    ) -> JoinHandle<()> {
        const PRECISION: u64 = 1; // Timing burst precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;
        let burst = self.rate / PRECISION;
        let mut counter = 0; // Identifies sample transactions.

        // Initiate the generator of dumb requests.
        let tx_maker = DumbCoinRequestMaker::new(description_hash);

        // Connect to the authorities.
        let connection_handlers = self.connect(tx_certificate);

        // Submit requests.
        tokio::spawn(async move {
            // Submit all transactions.
            let interval = interval(Duration::from_millis(BURST_DURATION));
            tokio::pin!(interval);

            // NOTE: This log entry is used to compute performance.
            info!("Start sending transactions");

            if burst == 0 {
                info!("No transactions to submit (burst={})", burst);
                return;
            }

            'main: loop {
                interval.tick().await;
                let now = Instant::now();
                for x in 0..burst {
                    let (bytes, id) = tx_maker.make_lock_request(x, counter, burst);

                    if x == counter % burst {
                        // NOTE: This log entry is used to compute performance.
                        info!("Sending sample transaction {}", id);
                    }

                    for handler in &connection_handlers {
                        if let Err(e) = handler
                            .send(bytes.clone())
                            .await
                            .map_err(|_| BenchError::ConnectionDropped)
                        {
                            warn!("{}", e);
                            break 'main;
                        }
                    }
                }
                counter += 1;

                if now.elapsed().as_millis() > BURST_DURATION as u128 {
                    // NOTE: This log entry is used to compute performance.
                    warn!("Transaction rate too high for this client");
                }
            }
        })
    }

    fn send_certificates(
        &self,
        mut rx_certificate: Receiver<Bytes>,
        description: CoinCreationDescription,
    ) -> JoinHandle<()> {
        let (tx_response, mut rx_response) = channel(CHANNEL_CAPACITY);

        // Initiate the generator of dumb certificates.
        let tx_maker = DumbLockCertificateMaker {
            committee: self.committee.clone(),
            description,
        };

        // Connect to the authorities.
        let connection_handlers = self.connect(tx_response);

        // Try to assemble certificates and disseminate them.
        tokio::spawn(async move {
            let mut lock_certificates_aggregators = HashMap::new();
            let mut last_lock_id = 0;
            let mut coins_aggregators = HashMap::new();
            let mut last_coin_id = 0;
            'main: loop {
                tokio::select! {
                    Some(bytes) = rx_certificate.recv() => {
                        match deserialize_message(&*bytes).unwrap() {
                            SerializedMessage::InfoResponse(response) => {
                                let id = response
                                    .account_id
                                    .sequence_number()
                                    .unwrap()
                                    .0;

                                // Ensures `aggregators` does not make use run out of memory.
                                if id < last_lock_id {
                                    debug!("Drop vote {} (<{})", id, last_lock_id);
                                    continue;
                                }

                                // Check if we got a certificate.
                                let account_id = response.account_id.clone();
                                if let Some(bytes) = tx_maker.try_make_certificate(response, &mut lock_certificates_aggregators).unwrap() {
                                    lock_certificates_aggregators
                                        .retain(|k, _| k.sequence_number().unwrap() >= account_id.sequence_number().unwrap());
                                    last_lock_id = id;

                                    // NOTE: This log entry is used to compute performance.
                                    info!("Assembled lock certificate {}", id);

                                    for handler in &connection_handlers {
                                        if let Err(e) = handler
                                            .send(bytes.clone())
                                            .await
                                            .map_err(|_| BenchError::ConnectionDropped)
                                        {
                                            warn!("{}", e);
                                            break 'main;
                                        }
                                    }
                                }
                                Ok(())
                            },
                            SerializedMessage::Error(e) => Err(BenchError::SerializationError(e.to_string())),
                            reply => Err(BenchError::UnexpectedReply(reply))
                        }
                        .unwrap()
                    },
                    Some(bytes) = rx_response.recv() => {
                        match deserialize_message(&*bytes).unwrap() {
                            SerializedMessage::CoinCreationResponse(response) => {
                                let CoinCreationResponse { tracking_id, .. } = *response;
                                let id = tracking_id.sequence_number().unwrap();

                                // Ensures `aggregators` does not make use run out of memory.
                                if id.0 < last_coin_id {
                                    debug!("Drop coin share {} (<{})", id, last_coin_id);
                                    continue;
                                }

                                if let Some(_tracking_id) = tx_maker.try_assemble_coins(tracking_id, &mut coins_aggregators) {
                                    coins_aggregators.retain(|k, _| k.sequence_number().unwrap() >= id);
                                    last_coin_id = id.0;

                                    // NOTE: This log entry is used to compute performance.
                                    info!("Assembled coin {}", id);
                                }
                                Ok(())
                            },
                            SerializedMessage::Error(e) => Err(BenchError::SerializationError(e.to_string())),
                            reply => Err(BenchError::UnexpectedReply(reply)),
                        }.unwrap()
                    },
                    else => break
                }
            }
        })
    }

    /// Run the benchmark.
    pub async fn benchmark(&self) -> Result<(), BenchError> {
        let (tx_certificate, rx_certificate) = channel(CHANNEL_CAPACITY);
        let (description, description_hash) = make_coins(
            &self.master_secret,
            &self.coconut_parameters,
            &self.coconut_verification_key,
        );
        let handler_1 = self.send_requests(tx_certificate, description_hash);
        let handler_2 = self.send_certificates(rx_certificate, description);
        try_join(handler_1, handler_2)
            .await
            .map(|_| ())
            .map_err(BenchError::from)
    }
}
