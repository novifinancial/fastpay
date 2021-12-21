mod client;
mod connection;
mod error;
mod transaction_maker;

use crate::client::BenchmarkClient;
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use fastpay::config::{CommitteeConfig, Import as _};
use std::{net::SocketAddr, path::Path};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for FastPay.")
        .args_from_usage(
            "<ADDR>... 'The network addresses of the shard where to send txs'
            --committee=<FILE> 'The file containing committee information'
            --others=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'
            --rate=<INT> 'The rate (txs/s) at which to send the transactions'"
        )
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    // Set the logger.
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Read the input parameters.
    let targets = matches
        .values_of("ADDR")
        .unwrap()
        .into_iter()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;

    let committee_config_path = Path::new(matches.value_of("committee").unwrap());
    let committee = CommitteeConfig::read(committee_config_path)
        .expect("Fail to read committee config")
        .into_committee();
    log::warn!(
        "{:?}",
        CommitteeConfig::read(committee_config_path).unwrap()
    );

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

    // Build the benchmark client and print its parameters.
    let client = BenchmarkClient::new(targets, committee, others, rate);
    client.print_parameters();

    // Wait for all authorities to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client
        .benchmark()
        .await
        .context("Failed to submit transactions")
}
