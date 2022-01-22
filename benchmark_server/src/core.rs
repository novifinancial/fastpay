// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{config::CommitteeConfig, receiver::MessageHandler, reliable_sender::ReliableSender};
use async_trait::async_trait;
use bytes::Bytes;
use fastpay_core::{
    authority::{Authority, AuthorityState, CrossShardContinuation},
    base_types::AuthorityName,
    error::FastPayError,
    serialize::{
        serialize_account_info_response, serialize_coin_creation_response,
        serialize_cross_shard_request, serialize_error, SerializedMessage,
    },
};
use log::{debug, warn};

pub struct Core {
    name: AuthorityName,
    committee: CommitteeConfig,
    state: AuthorityState,
    reliable_sender: ReliableSender,
}

impl Core {
    pub fn new(name: AuthorityName, committee: CommitteeConfig, state: AuthorityState) -> Self {
        Self {
            name,
            committee,
            state,
            reliable_sender: ReliableSender::new(),
        }
    }

    async fn handle_continuation(&mut self, continuation: CrossShardContinuation) {
        if let CrossShardContinuation::Request { shard_id, request } = continuation {
            let buffer = serialize_cross_shard_request(&request);
            debug!(
                "Scheduling cross shard query: {} -> {}",
                self.state.shard_id, shard_id
            );
            let address = self
                .committee
                .shard(&self.name, &shard_id)
                .expect("Shard does not exist");
            self.reliable_sender
                .send(address, Bytes::from(buffer))
                .await;
        }
    }
}

#[async_trait]
impl MessageHandler for Core {
    async fn handle_message(&mut self, message: SerializedMessage) -> Option<Vec<u8>> {
        debug!("Received {:?}", message);
        let reply = match message {
            SerializedMessage::RequestOrder(message) => self
                .state
                .handle_request_order(*message)
                .map(|info| Some(serialize_account_info_response(&info))),
            SerializedMessage::ConfirmationOrder(message) => {
                match self.state.handle_confirmation_order(*message) {
                    Ok((info, continuation)) => {
                        // Cross-shard request
                        self.handle_continuation(continuation).await;
                        // Response
                        Ok(Some(serialize_account_info_response(&info)))
                    }
                    Err(error) => Err(error),
                }
            }
            SerializedMessage::CoinCreationOrder(message) => {
                match self.state.handle_coin_creation_order(*message) {
                    Ok((response, continuations)) => {
                        // Cross-shard requests
                        for continuation in continuations {
                            self.handle_continuation(continuation).await;
                        }
                        // Response
                        Ok(Some(serialize_coin_creation_response(&response)))
                    }
                    Err(error) => Err(error),
                }
            }
            SerializedMessage::CrossShardRequest(request) => {
                if let Err(e) = self.state.handle_cross_shard_request(*request) {
                    panic!("Failed to handle cross-shard request: {}", e);
                }
                // No user to respond to.
                Ok(None)
            }
            _ => Err(FastPayError::UnexpectedMessage),
        };

        match reply {
            Ok(x) => x,
            Err(error) => {
                warn!("User query failed: {}", error);
                Some(serialize_error(&error))
            }
        }
    }
}
