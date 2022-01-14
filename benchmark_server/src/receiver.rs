// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use bytes::Bytes;
use fastpay_core::serialize::{deserialize_message, SerializedMessage};
use futures::{stream::StreamExt as _, SinkExt as _};
use log::{debug, info, warn};
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[async_trait]
pub trait MessageHandler {
    async fn handle_message(&mut self, message: SerializedMessage) -> Option<Vec<u8>>;
}

/// A simple network server used for benchmarking.
pub struct NetworkReceiver {
    /// The network address of the server.
    address: String,
    /// Keeps a channel to each client connection.
    handles: HashMap<SocketAddr, Sender<Bytes>>,
}

impl NetworkReceiver {
    pub async fn spawn<H>(address: String, handler: H)
    where
        H: MessageHandler + Send + 'static,
    {
        Self {
            address,
            handles: HashMap::new(),
        }
        .run(handler)
        .await
    }

    async fn run<H>(&mut self, mut handler: H)
    where
        H: MessageHandler + Send + 'static,
    {
        let (tx_request, mut rx_request) = channel(1_000);
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("Failed to bind TCP port");

        debug!("Listening on {}", self.address);
        loop {
            tokio::select! {
                result = listener.accept() => match result {
                    Ok((socket, peer)) => {
                        info!("Incoming connection established with {}", peer);
                        let (tx_reply, rx_reply) = channel(1_000);
                        self.handles.insert(peer, tx_reply);

                        // TODO: cleanup the hashmap self.handles when this task ends.
                        Self::spawn_connection(socket, peer, tx_request.clone(), rx_reply);
                    },
                    Err(e) => {
                        warn!("Failed to listen to client request: {}", e);
                    }
                },
                Some((peer, bytes)) = rx_request.recv() => {
                    if let Some(sender) = self.handles.get(&peer) {
                        match deserialize_message(&*bytes) {
                            Ok(message) => {
                                if let Some(reply) = handler.handle_message(message).await {
                                    if let Err(e) = sender
                                        .send(Bytes::from(reply))
                                        .await
                                    {
                                        warn!("Failed to send reply to connection task: {}", e);
                                        continue;
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Invalid message encoding: {}", e);
                                continue;
                            }
                        }
                    }
                },
                else => break
            }
        }
    }

    fn spawn_connection(
        socket: TcpStream,
        peer: SocketAddr,
        tx_request: Sender<(SocketAddr, Bytes)>,
        mut rx_reply: Receiver<Bytes>,
    ) {
        tokio::spawn(async move {
            let transport = Framed::new(socket, LengthDelimitedCodec::new());
            let (mut writer, mut reader) = transport.split();
            loop {
                tokio::select! {
                    Some(frame) = reader.next() => match frame {
                        Ok(message) => {
                            if let Err(e) = tx_request
                            .send((peer, message.freeze()))
                            .await {
                                warn!("Failed to send message to main network task: {}", e);
                                break;
                            }
                        },
                        Err(e) => {
                            warn!("Failed to read TCP stream: {}", e);
                            break;
                        }
                    },
                    Some(reply) = rx_reply.recv() => {
                        if let Err(e) = writer.send(reply).await {
                            warn!("Failed to send reply to client: {}", e);
                            break;
                        }
                    },
                    else => break
                }
            }
            info!("Connection closed");
        });
    }
}
