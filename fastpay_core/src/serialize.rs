// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::messages::*;
use crate::error::*;

use failure::format_err;
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "unit_tests/serialize_tests.rs"]
mod serialize_tests;

#[derive(Serialize, Deserialize, Debug)]
pub enum SerializedMessage {
    // Inbound
    RequestOrder(Box<RequestOrder>),
    ConfirmationOrder(Box<ConfirmationOrder>),
    CoinCreationOrder(Box<CoinCreationOrder>),
    InfoQuery(Box<AccountInfoQuery>),
    // Outbound
    Vote(Box<Vote>),
    Votes(Vec<Vote>),
    InfoResponse(Box<AccountInfoResponse>),
    Error(Box<FastPayError>),
    // Internal to an authority
    CrossShardRequest(Box<CrossShardRequest>),
}

// This helper structure is only here to avoid cloning while serializing commands.
// Here we must replicate the definition of SerializedMessage exactly
// so that the variant tags match.
#[derive(Serialize)]
enum ShallowSerializedMessage<'a> {
    // Inbound
    RequestOrder(&'a RequestOrder),
    ConfirmationOrder(&'a ConfirmationOrder),
    CoinCreationOrder(&'a CoinCreationOrder),
    InfoQuery(&'a AccountInfoQuery),
    // Outbound
    Vote(&'a Vote),
    Votes(&'a [Vote]),
    InfoResponse(&'a AccountInfoResponse),
    Error(&'a FastPayError),
    // Internal to an authority
    CrossShardRequest(&'a CrossShardRequest),
}

fn serialize_into<T, W>(writer: W, msg: &T) -> Result<(), failure::Error>
where
    W: std::io::Write,
    T: Serialize,
{
    bincode::serialize_into(writer, msg).map_err(|err| format_err!("{}", err))
}

fn serialize<T>(msg: &T) -> Vec<u8>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    bincode::serialize_into(&mut buf, msg)
        .expect("Serializing to a resizable buffer should not fail.");
    buf
}

pub fn serialize_message(msg: &SerializedMessage) -> Vec<u8> {
    serialize(msg)
}

pub fn serialize_request_order(value: &RequestOrder) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::RequestOrder(value))
}

pub fn serialize_request_order_into<W>(
    writer: W,
    value: &RequestOrder,
) -> Result<(), failure::Error>
where
    W: std::io::Write,
{
    serialize_into(writer, &ShallowSerializedMessage::RequestOrder(value))
}

pub fn serialize_error(value: &FastPayError) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::Error(value))
}

pub fn serialize_confirmation_order(value: &ConfirmationOrder) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::ConfirmationOrder(value))
}

pub fn serialize_confirmation_order_into<W>(
    writer: W,
    value: &ConfirmationOrder,
) -> Result<(), failure::Error>
where
    W: std::io::Write,
{
    serialize_into(writer, &ShallowSerializedMessage::ConfirmationOrder(value))
}

pub fn serialize_info_query(value: &AccountInfoQuery) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::InfoQuery(value))
}

pub fn serialize_info_response(value: &AccountInfoResponse) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::InfoResponse(value))
}

pub fn serialize_cross_shard_request(value: &CrossShardRequest) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::CrossShardRequest(value))
}

pub fn serialize_coin_creation_order(value: &CoinCreationOrder) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::CoinCreationOrder(value))
}

pub fn serialize_votes(value: &[Vote]) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::Votes(value))
}

pub fn serialize_vote(value: &Vote) -> Vec<u8> {
    serialize(&ShallowSerializedMessage::Vote(value))
}

pub fn serialize_vote_into<W>(writer: W, value: &Vote) -> Result<(), failure::Error>
where
    W: std::io::Write,
{
    serialize_into(writer, &ShallowSerializedMessage::Vote(value))
}

pub fn deserialize_message<R>(reader: R) -> Result<SerializedMessage, failure::Error>
where
    R: std::io::Read,
{
    bincode::deserialize_from(reader).map_err(|err| format_err!("{}", err))
}
