// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use fastpay_core::{
    base_types::{AuthorityName, KeyPair, ShardId},
    committee::{CoconutSetup, Committee},
};
use log::info;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::net::SocketAddr;
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
};

pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, std::io::Error> {
        let data = fs::read(path)?;
        Ok(serde_json::from_slice(data.as_slice())?)
    }
}

pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), std::io::Error> {
        let file = OpenOptions::new().create(true).write(true).open(path)?;
        let mut writer = BufWriter::new(file);
        let data = serde_json::to_string_pretty(self).unwrap();
        writer.write_all(data.as_ref())?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Parameters {
    pub coconut_setup: Option<CoconutSetup>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            coconut_setup: None,
        }
    }
}

impl Import for Parameters {}
impl Export for Parameters {}

impl Parameters {
    pub fn log(&self) {
        if self.coconut_setup.is_some() {
            info!("This authority is coconut-enabled!");
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct MasterSecret {
    pub master_secret: coconut::SecretKey,
}

impl Import for MasterSecret {}
impl Export for MasterSecret {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityConfig {
    shards: HashMap<ShardId, SocketAddr>,
}

impl Import for AuthorityConfig {}
impl Export for AuthorityConfig {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommitteeConfig {
    authorities: HashMap<AuthorityName, AuthorityConfig>,
}

impl Import for CommitteeConfig {}
impl Export for CommitteeConfig {}

impl CommitteeConfig {
    pub fn into_committee(self, coconut_setup: Option<CoconutSetup>) -> Committee {
        Committee::new(self.voting_rights(), coconut_setup)
    }

    fn voting_rights(&self) -> BTreeMap<AuthorityName, usize> {
        let mut map = BTreeMap::new();
        for name in self.authorities.keys() {
            map.insert(*name, 1);
        }
        map
    }

    pub fn num_shards(&self, myself: &AuthorityName) -> Option<usize> {
        self.authorities.get(myself).map(|x| x.shards.len())
    }

    pub fn shard(&self, myself: &AuthorityName, id: &ShardId) -> Option<SocketAddr> {
        self.authorities
            .get(myself)
            .map(|authority| authority.shards.get(id))
            .flatten()
            .copied()
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyConfig {
    pub name: AuthorityName,
    pub key: KeyPair,
    pub coconut_key: Option<coconut::KeyPair>,
}

impl KeyConfig {
    pub fn new(num_authorities: usize) -> (Vec<KeyConfig>, CoconutSetup, MasterSecret) {
        let mut rng = coconut::rand::thread_rng();
        let parameters = coconut::Parameters::new(3, /* max_output_coins */ 2);
        let threshold = (2 * num_authorities + 1) / 3;
        let (verification_key, key_pairs, master_secret) =
            coconut::KeyPair::ttp_and_master_key(&mut rng, &parameters, threshold, num_authorities);

        let mut coconut_authorities = BTreeMap::new();
        let mut config_authorities = Vec::new();
        for coconut_key_pair in key_pairs {
            let key = KeyPair::generate();
            let name = key.public();

            let index = coconut_key_pair.index;
            let public_key = coconut_key_pair.public.clone();
            let config = KeyConfig {
                name,
                key,
                coconut_key: Some(coconut_key_pair),
            };

            coconut_authorities.insert(name, (index, public_key));
            config_authorities.push(config);
        }
        let coconut_setup = CoconutSetup {
            parameters,
            verification_key,
            authorities: coconut_authorities,
        };
        let master_secret = MasterSecret { master_secret };
        (config_authorities, coconut_setup, master_secret)
    }
}

impl Import for KeyConfig {}
impl Export for KeyConfig {}
