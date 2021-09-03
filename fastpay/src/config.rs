// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::transport::NetworkProtocol;
use fastpay_core::{
    base_types::*,
    client::ClientState,
    messages::{Address, CertifiedTransferOrder},
};

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityConfig {
    pub network_protocol: NetworkProtocol,
    #[serde(
        serialize_with = "pubkey_as_base64",
        deserialize_with = "pubkey_from_base64"
    )]
    pub name: AuthorityName,
    pub host: String,
    pub base_port: u32,
    pub num_shards: u32,
}

impl AuthorityConfig {
    pub fn print(&self) {
        let data = serde_json::to_string(self).unwrap();
        println!("{}", data);
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthorityServerConfig {
    pub authority: AuthorityConfig,
    pub key: KeyPair,
}

impl AuthorityServerConfig {
    pub fn read(path: &str) -> Result<Self, std::io::Error> {
        let data = fs::read(path)?;
        Ok(serde_json::from_slice(data.as_slice())?)
    }

    pub fn write(&self, path: &str) -> Result<(), std::io::Error> {
        let file = OpenOptions::new().create(true).write(true).open(path)?;
        let mut writer = BufWriter::new(file);
        let data = serde_json::to_string_pretty(self).unwrap();
        writer.write_all(data.as_ref())?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}

pub struct CommitteeConfig {
    pub authorities: Vec<AuthorityConfig>,
}

impl CommitteeConfig {
    pub fn read(path: &str) -> Result<Self, std::io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let stream = serde_json::Deserializer::from_reader(reader).into_iter();
        Ok(Self {
            authorities: stream.filter_map(Result::ok).collect(),
        })
    }

    pub fn write(&self, path: &str) -> Result<(), std::io::Error> {
        let file = OpenOptions::new().create(true).write(true).open(path)?;
        let mut writer = BufWriter::new(file);
        for config in &self.authorities {
            serde_json::to_writer(&mut writer, config)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    pub fn voting_rights(&self) -> BTreeMap<AuthorityName, usize> {
        let mut map = BTreeMap::new();
        for authority in &self.authorities {
            map.insert(authority.name, 1);
        }
        map
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserAccount {
    pub account_id: AccountId,
    pub key: KeyPair,
    pub next_sequence_number: SequenceNumber,
    pub balance: Balance,
    pub sent_certificates: Vec<CertifiedTransferOrder>,
    pub received_certificates: Vec<CertifiedTransferOrder>,
}

impl UserAccount {
    pub fn new(account_id: AccountId, balance: Balance) -> Self {
        let (_, key) = get_key_pair();
        Self {
            account_id,
            key,
            next_sequence_number: SequenceNumber::new(),
            balance,
            sent_certificates: Vec::new(),
            received_certificates: Vec::new(),
        }
    }
}

pub struct AccountsConfig {
    accounts: BTreeMap<AccountId, UserAccount>,
}

impl AccountsConfig {
    pub fn get(&self, account_id: &AccountId) -> Option<&UserAccount> {
        self.accounts.get(account_id)
    }

    pub fn insert(&mut self, account: UserAccount) {
        self.accounts.insert(account.account_id.clone(), account);
    }

    pub fn num_accounts(&self) -> usize {
        self.accounts.len()
    }

    pub fn last_account(&mut self) -> Option<&UserAccount> {
        self.accounts.values().last()
    }

    pub fn accounts_mut(&mut self) -> impl Iterator<Item = &mut UserAccount> {
        self.accounts.values_mut()
    }

    pub fn update_from_state<A>(&mut self, state: &ClientState<A>) {
        let account = self
            .accounts
            .get_mut(state.account_id())
            .expect("Updated account should already exist");
        // account.key = state.secret().copy(); // TODO: support key rotations
        account.next_sequence_number = state.next_sequence_number();
        account.balance = state.balance();
        account.sent_certificates = state.sent_certificates().clone();
        account.received_certificates = state.received_certificates().cloned().collect();
    }

    pub fn update_for_received_transfer(&mut self, certificate: CertifiedTransferOrder) {
        let transfer = &certificate.value.transfer;
        if let Address::FastPay(recipient) = &transfer.recipient {
            if let Some(config) = self.accounts.get_mut(recipient) {
                if let Err(position) = config
                    .received_certificates
                    .binary_search_by_key(&certificate.value.key(), |order| order.value.key())
                {
                    config.balance = config.balance.try_add(transfer.amount.into()).unwrap();
                    config.received_certificates.insert(position, certificate)
                }
            }
        }
    }

    pub fn read_or_create(path: &str) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(path)?;
        let reader = BufReader::new(file);
        let stream = serde_json::Deserializer::from_reader(reader).into_iter();
        Ok(Self {
            accounts: stream
                .filter_map(Result::ok)
                .map(|account: UserAccount| (account.account_id.clone(), account))
                .collect(),
        })
    }

    pub fn write(&self, path: &str) -> Result<(), std::io::Error> {
        let file = OpenOptions::new().write(true).open(path)?;
        let mut writer = BufWriter::new(file);
        for account in self.accounts.values() {
            serde_json::to_writer(&mut writer, account)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }
}

pub struct InitialStateConfig {
    pub accounts: Vec<(AccountId, AccountOwner, Balance)>,
}

impl InitialStateConfig {
    pub fn read(path: &str) -> Result<Self, failure::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut accounts = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let elements = line.split(':').collect::<Vec<_>>();
            if elements.len() != 3 {
                failure::bail!("expecting three columns separated with ':'")
            }
            let id = decode_id(elements[0])?;
            let pubkey = decode_pubkey(elements[1])?;
            let balance = elements[2].parse()?;
            accounts.push((id, pubkey, balance));
        }
        Ok(Self { accounts })
    }

    pub fn write(&self, path: &str) -> Result<(), std::io::Error> {
        let file = OpenOptions::new().create(true).write(true).open(path)?;
        let mut writer = BufWriter::new(file);
        for (id, pubkey, balance) in &self.accounts {
            writeln!(
                writer,
                "{}:{}:{}",
                encode_id(id),
                encode_pubkey(pubkey),
                balance
            )?;
        }
        Ok(())
    }
}
