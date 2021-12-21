use crate::error::BenchError;
use bytes::Bytes;
use futures::{stream::StreamExt as _, SinkExt as _};
use log::{info, warn};
use std::net::SocketAddr;
use tokio::{
    net::TcpStream,
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// A connection is responsible to establish and keep alive (if possible) a connection with a single peer.
pub struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    rx_request: Receiver<Bytes>,
    /// Output the network replies.
    tx_reply: Sender<Bytes>,
}

impl Connection {
    pub fn spawn(address: SocketAddr, rx_request: Receiver<Bytes>, tx_reply: Sender<Bytes>) {
        tokio::spawn(async move {
            Self {
                address,
                rx_request,
                tx_reply,
            }
            .run()
            .await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        // Try to connect to the peer.
        let (mut writer, mut reader) = match TcpStream::connect(self.address).await {
            Ok(stream) => Framed::new(stream, LengthDelimitedCodec::new()).split(),
            Err(e) => {
                warn!("{}", BenchError::FailedToConnect(self.address, e));
                return;
            }
        };
        info!("Outgoing connection established with {}", self.address);

        // Transmit messages once we have established a connection.
        loop {
            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                Some(data) = self.rx_request.recv() => {
                    if let Err(e) = writer.send(data).await {
                        warn!("{}", BenchError::FailedToSendMessage(self.address, e));
                        return;
                    }
                },
                response = reader.next() => {
                    match response {
                        Some(Ok(bytes)) => self.tx_reply.send(bytes.freeze()).await.expect("Failed to send reply"),
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            warn!("{}", BenchError::FailedToReceiveReply(self.address));
                            return;
                        }
                    }
                },
            }
        }
    }
}
