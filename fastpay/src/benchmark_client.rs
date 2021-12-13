use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use fastpay_core::{base_types::*, messages::*, serialize::serialize_request_order};
use futures::future::join_all;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{info, warn};
use rand::Rng;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for FastPay.")
        .args_from_usage(
            "<ADDR> 'The network address of the authority's shard where to send txs'
            --others=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'
            --rate=<INT> 'The rate (txs/s) at which to send the transactions'"
        )
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let target = matches
        .value_of("ADDR")
        .unwrap()
        .parse::<SocketAddr>()
        .context("Invalid socket address format")?;
    let others = matches
        .values_of("others")
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;

    info!("Target shard address: {}", target);
    info!("Transactions rate: {} tx/s", rate);
    let client = BenchmarkClient {
        target,
        others,
        rate,
    };

    // Wait for all authorities to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client.send().await.context("Failed to submit transactions")
}

struct BenchmarkClient {
    target: SocketAddr,
    others: Vec<SocketAddr>,
    rate: u64,
}

impl BenchmarkClient {
    pub async fn wait(&self) {
        // Wait for all authorities to be online.
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

    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 20; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // Connect to the mempool.
        let stream = TcpStream::connect(self.target)
            .await
            .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        let burst = self.rate / PRECISION;
        let mut counter = 0;
        let mut r = rand::thread_rng().gen();
        let key_pair = KeyPair::generate();
        let (mut writer, mut reader) = Framed::new(stream, LengthDelimitedCodec::new()).split();
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        'main: loop {
            tokio::select! {
                _ = interval.tick() => {

                    let now = Instant::now();
                    for x in 0..burst {
                        let bytes = Self::make_request(x, counter, burst, r, &key_pair);
                        if let Err(e) = writer.send(bytes).await {
                            warn!("Failed to send transaction: {}", e);
                            break 'main;
                        }
                    }
                    r += 1;
                    counter += 1;

                    if now.elapsed().as_millis() > BURST_DURATION as u128 {
                        // NOTE: This log entry is used to compute performance.
                        warn!("Transaction rate too high for this client");
                    }
                },
                response = reader.next() => match response {
                    Some(Ok(bytes)) => {
                        // TODO: Retrieve partial certificates, assemble certificates, and
                        // broadcast certificates to the authorities.
                        warn!("{:?}", bytes);
                    },
                    Some(Err(e)) => {
                        warn!("Failed to read authority's reply: {}", e);
                        break 'main;
                    },
                    None => {
                        warn!("Authority dropped the channel");
                        break 'main;
                    }
                }
            }
        }
        Ok(())
    }

    fn make_request(x: u64, counter: u64, burst: u64, r: u64, key_pair: &KeyPair) -> Bytes {
        // Create the sender and receiver ensuring they don't clash.
        let sender = AccountId::new(vec![
            SequenceNumber::new(),
            SequenceNumber::from(x),
            SequenceNumber::from(r),
        ]);
        let recipient = AccountId::new(vec![
            SequenceNumber::from(x),
            SequenceNumber::new(),
            SequenceNumber::from(r),
        ]);

        // We will use the user-data to distinguish sample transactions.
        let user_data = if x == counter % burst {
            let mut data = [0u8; 32];
            data[..8].clone_from_slice(&counter.to_le_bytes());
            UserData(Some(data))
        } else {
            UserData::default()
        };

        // Make a transfer request for 1 coin.
        let request = Request {
            account_id: sender,
            operation: Operation::Transfer {
                recipient: Address::FastPay(recipient),
                amount: Amount::from(1),
                user_data: user_data.clone(),
            },
            sequence_number: SequenceNumber::new(),
        };
        let order = RequestOrder::new(request.into(), key_pair, Vec::new());
        let serialized_order = serialize_request_order(&order);

        if user_data.0.is_some() {
            info!("Sending sample transaction {}", counter);
        }

        Bytes::from(serialized_order)
    }
}
