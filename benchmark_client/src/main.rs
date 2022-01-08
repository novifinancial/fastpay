// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

mod client;
mod coco_client;
mod connection;
mod error;
mod transaction_maker;

use crate::client::BenchmarkClient;
use crate::coco_client::CocoBenchmarkClient;
use anyhow::{Context, Result};
use benchmark_server::config::{CommitteeConfig, Import, MasterSecret, Parameters};
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for FastPay.")
        .args_from_usage(
            "<ADDR>... 'The network addresses of the shard where to send txs'
            --committee=<FILE> 'The file containing committee information'
            --others=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'
            --rate=<INT> 'The rate (txs/s) at which to send the transactions'
            --parameters=[FILE] 'The file containing the node parameters'
            --master_secret=[FILE] 'The file containing the coconut master secret key"
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

    let committee_config_path = matches.value_of("committee").unwrap();
    let committee = CommitteeConfig::import(committee_config_path)
        .expect("Fail to read committee config")
        .into_committee(None);

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

    match matches.value_of("parameters") {
        Some(filename) => {
            let coconut_setup = Parameters::import(filename)
                .context("Failed to load the node's parameters")?
                .coconut_setup
                .unwrap();
            let coconut_parameters = coconut_setup.parameters;
            let verification_key = coconut_setup.verification_key;

            let master_secret_file = matches
                .value_of("master_secret")
                .context("provided parameters but not master secret")
                .unwrap();
            let master_secret = MasterSecret::import(master_secret_file)
                .context("Failed to load master secret key")?
                .master_secret;

            // Build the benchmark client and print its parameters.
            let client = CocoBenchmarkClient::new(
                targets,
                committee,
                others,
                rate,
                master_secret,
                coconut_parameters,
                verification_key,
            );
            client.print_parameters();

            // Wait for all authorities to be online and synchronized.
            client.wait().await;

            // Start the benchmark.
            client
                .benchmark()
                .await
                .context("Failed to submit transactions")
        }
        None => {
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
    }
}
