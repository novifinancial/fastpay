use crate::{
    connection::Connection,
    error::NetworkError,
    transaction_maker::{DumbCertificateMaker, DumbRequestMaker},
};
use bytes::Bytes;
use fastpay_core::{
    committee::Committee,
    serialize::{deserialize_message, SerializedMessage},
};
use futures::future::{join_all, try_join};
use log::{info, warn};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Receiver, Sender},
    task::{JoinError, JoinHandle},
    time::{interval, sleep, Duration, Instant},
};

/// The default channel capacity.
const CHANNEL_CAPACITY: usize = 1_000;

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

    fn send_requests(&self, tx_certificate: Sender<Bytes>) -> JoinHandle<()> {
        const PRECISION: u64 = 20; // Timing burst precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;
        let burst = self.rate / PRECISION;
        let mut counter = 0; // Identifies sample transactions.

        // Initiate the generator of dumb requests.
        let tx_maker = DumbRequestMaker::new();

        // Connect to the authorities.
        let connection_handlers = self.connect(tx_certificate);

        // Submit requests.
        tokio::spawn(async move {
            // Submit all transactions.
            let interval = interval(Duration::from_millis(BURST_DURATION));
            tokio::pin!(interval);

            // NOTE: This log entry is used to compute performance.
            info!("Start sending transactions");

            loop {
                interval.tick().await;
                let now = Instant::now();
                for x in 0..burst {
                    let bytes = tx_maker.make_request(x, counter, burst);
                    for handler in &connection_handlers {
                        handler
                            .send(bytes.clone())
                            .await
                            .map_err(|_| NetworkError::ConnectionDropped)
                            .unwrap();
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

    fn send_certificates(&self, mut rx_certificate: Receiver<Bytes>) -> JoinHandle<()> {
        let (tx_response, mut rx_response) = channel(CHANNEL_CAPACITY);

        // Initiate the generator of dumb certificates.
        let tx_maker = DumbCertificateMaker {
            committee: self.committee.clone(),
        };

        // Connect to the authorities.
        let connection_handlers = self.connect(tx_response);

        // Try to assemble certificates and disseminate them.
        tokio::spawn(async move {
            let mut aggregators = HashMap::new();
            loop {
                tokio::select! {
                    Some(bytes) = rx_certificate.recv() => {
                        match deserialize_message(&*bytes).unwrap() {
                            SerializedMessage::InfoResponse(response) => {
                                if let Some(bytes) = tx_maker.try_make_certificate(response, &mut aggregators).unwrap() {
                                    for handler in &connection_handlers {
                                        handler
                                            .send(bytes.clone())
                                            .await
                                            .map_err(|_| NetworkError::ConnectionDropped).unwrap();
                                    }
                                }
                                Ok(())
                            },
                            SerializedMessage::Error(e) => Err(NetworkError::SerializationError(e.to_string())),
                            reply @ _ => Err(NetworkError::UnexpectedReply(reply))
                        }
                        .unwrap()
                    },
                    Some(_) = rx_response.recv() => {
                        // Sink responses.
                    }
                }
            }
        })
    }

    /// Run the benchmark.
    pub async fn benchmark(&self) -> Result<(), JoinError> {
        let (tx_certificate, rx_certificate) = channel(CHANNEL_CAPACITY);
        let handler_1 = self.send_requests(tx_certificate);
        let handler_2 = self.send_certificates(rx_certificate);
        try_join(handler_1, handler_2).await.map(|_| ())
    }
}
