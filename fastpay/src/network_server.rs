use crate::transport::{MessageHandler, SpawnedServer};
use bytes::Bytes;
use futures::{future, stream::StreamExt as _, SinkExt as _};
use log::{debug, info, warn};
use tokio::net::TcpListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// A simple network server used for benchmarking.
pub struct BenchmarkServer {
    /// The network address of the server.
    address: String,
}

impl BenchmarkServer {
    pub fn spawn<H>(address: String, handler: H) -> Result<SpawnedServer, std::io::Error>
    where
        H: MessageHandler + Send + 'static,
    {
        let (complete, receiver) = futures::channel::oneshot::channel();
        let handle = tokio::spawn(async move { Self { address }.run(handler, receiver).await });
        Ok(SpawnedServer { complete, handle })
    }

    async fn run<H>(
        &self,
        mut handler: H,
        mut exit_future: futures::channel::oneshot::Receiver<()>,
    ) -> Result<(), std::io::Error>
    where
        H: MessageHandler + Send + 'static,
    {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("Failed to bind TCP port");

        debug!("Listening on {}", self.address);
        loop {
            let (socket, peer) =
                match future::select(exit_future, Box::pin(listener.accept())).await {
                    future::Either::Left(_) => {
                        warn!("Failed to listen to client request");
                        break;
                    }
                    future::Either::Right((value, new_exit_future)) => {
                        exit_future = new_exit_future;
                        value?
                    }
                };

            info!("Incoming connection established with {}", peer);

            let transport = Framed::new(socket, LengthDelimitedCodec::new());
            let (mut writer, mut reader) = transport.split();
            while let Some(frame) = reader.next().await {
                match frame {
                    Ok(message) => {
                        if let Some(reply) = handler.handle_message(&message.freeze()).await {
                            if let Err(e) = writer.send(Bytes::from(reply)).await {
                                warn!("Failed to send reply to client: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error while reading TCP stream: {}", e);
                        break;
                    }
                }
            }
            info!("Connection closed by peer {}", peer);
        }
        Ok(())
    }
}
