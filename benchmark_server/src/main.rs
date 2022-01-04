mod config;
mod core;
mod error;
mod receiver;
mod reliable_sender;

use crate::config::{CommitteeConfig, KeyConfig, Parameters};
use crate::config::{Export, Import};
use crate::core::Core;
use crate::receiver::NetworkReceiver;
use anyhow::{Context, Result};
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use env_logger::Env;
use fastpay_core::authority::AuthorityState;
use fastpay_core::base_types::ShardId;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Zef.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_all")
                .about("Print a fresh key pair to file")
                .args_from_usage(
                    "<FILE>... 'The filenames containing the private config of each authority'
                    --committee_size=<INT> 'The committee size'",
                ),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run an authority")
                .args_from_usage(
                    "--keys=<FILE> 'The file containing the node keys'
                    --committee=<FILE> 'The file containing committee information'
                    --parameters=[FILE] 'The file containing the node parameters'
                    --store=<PATH> 'The path where to create the data store'
                    --id=<INT> 'The worker id'",
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    match matches.subcommand() {
        ("generate_all", Some(sub_matches)) => generate_all(sub_matches)?,
        ("run", Some(sub_matches)) => run(sub_matches).await?,
        _ => unreachable!(),
    }
    Ok(())
}

fn generate_all(matches: &ArgMatches<'_>) -> Result<()> {
    let filenames = matches.values_of("FILE").unwrap();
    let committee_size = matches
        .value_of("committee_size")
        .unwrap()
        .parse::<usize>()
        .context("The committee size must be a positive integer")?;

    let (keypairs, coconut_setup) = KeyConfig::new(committee_size);
    for (filename, keypair) in filenames.into_iter().zip(keypairs.into_iter()) {
        keypair
            .export(filename)
            .context("Failed to generate key pair")?
    }
    Parameters {
        coconut_setup: Some(coconut_setup),
    }
    .export("parameters.json")
    .context("Failed to export coconut setup")
}

async fn run(matches: &ArgMatches<'_>) -> Result<()> {
    let key_file = matches.value_of("keys").unwrap();
    let committee_file = matches.value_of("committee").unwrap();
    let parameters_file = matches.value_of("parameters");
    let _store_path = matches.value_of("store").unwrap();
    let shard_id = matches
        .value_of("id")
        .unwrap()
        .parse::<ShardId>()
        .context("The worker id must be a positive integer")?;

    // Read the committee and node's keypair from file.
    let keypair = KeyConfig::import(key_file).context("Failed to load the node's keypair")?;
    let committee = CommitteeConfig::import(committee_file)
        .context("Failed to load the committee information")?;

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    // Make the data store.
    //let store = Store::new(store_path).context("Failed to create a store")?;

    // Spawn a shard.
    Server::spawn(keypair, shard_id, committee, parameters).await;

    // If this expression is reached, the program ends and all other tasks terminate.
    unreachable!();
}

pub struct Server;

impl Server {
    pub async fn spawn(
        keypair: KeyConfig,
        shard_id: ShardId,
        committee: CommitteeConfig,
        parameters: Parameters,
    ) {
        // NOTE: This log entry is used to compute performance.
        parameters.log();

        let name = keypair.name;
        let key = keypair.key;
        let coconut_key = keypair.coconut_key;
        let num_shards = committee
            .num_shards(&name)
            .expect("Our key is not in the committee");
        let address = committee
            .shard(&name, &shard_id)
            .expect("Our key is not in the committee");

        // NOTE: This log entry is used to compute performance.
        info!("Shard booted on {}", address.ip());

        let state = AuthorityState::new_shard(
            committee.clone().into_committee(parameters.coconut_setup),
            key,
            coconut_key,
            shard_id,
            num_shards as u32,
        );

        let core = Core::new(name, committee, state);

        NetworkReceiver::spawn(address.to_string(), core).await;
    }
}
