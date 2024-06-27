//! The engine drives all communication.
//!
//! Note: This app IP as identifier for each device. You should not do that when running UDP
//! unless you have authentication on the packets, as UDP source addresses are trivial to spoof.

use embedded_dtls::{
    queue_helpers::framed_queue,
    server::{
        config::{Identity, Key, ServerConfig},
        open_server,
    },
};
use log::*;
use once_cell::sync::{Lazy, OnceCell};
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use tokio::{
    net::UdpSocket,
    sync::{
        broadcast,
        mpsc::{channel, error::TrySendError, Receiver, Sender},
        RwLock,
    },
};

use rpc_definition::{
    postcard_rpc::host_client::HostClient,
    wire_error::{FatalError, ERROR_PATH},
};

use crate::ingress::engine::edtls::Delay;

/// The new state of a connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    /// A new connection was established.
    New(IpAddr),
    /// A connection was dropped.
    Closed(IpAddr),
}

/// Global singleton for the UDP socket.
///
/// RX happens in `udp_listener`, TX in `communication_worker`.
static SOCKET: OnceCell<UdpSocket> = OnceCell::new();

/// Core socket listener, handles all incoming packets.
///
/// This should run until the app closes.
pub async fn udp_listener(socket: UdpSocket) -> ! {
    let socket = SOCKET.get_or_init(|| socket);

    // Wire workers are handling RX/TX packets, one worker per IP connected.
    let mut wire_workers = FxHashMap::default();
    wire_workers.reserve(1000);

    debug!("Waiting for connections...");

    loop {
        let mut rx_buf = Vec::with_capacity(2048);

        let Ok((len, from)) = socket.recv_buf_from(&mut rx_buf).await else {
            error!("The socket was unable to receive data");
            continue;
        };
        assert_eq!(rx_buf.len(), len); // Assumption: We don't need `len`.

        let ip = from.ip();

        // Find existing RX/TX worker or create a new one.
        let worker = wire_workers
            .entry(ip)
            .or_insert_with(|| create_communication_worker(ip));

        // Send packet to the worker, or create it again if it has closed its connection.
        if let Err(e) = worker.try_send(rx_buf) {
            match e {
                TrySendError::Full(_) => {
                    error!("{ip}: Can't keep up with incoming packets");
                }
                TrySendError::Closed(retry_payload) => {
                    // Recreate the worker if the old one has shut down.
                    // This can happen when a device was connected, shut down, and connected again.
                    wire_workers.insert(ip, create_communication_worker(ip));

                    if let Err(e) = wire_workers.get_mut(&ip).unwrap().try_send(retry_payload) {
                        error!(
                            "{}: Retry worker failed to start with error {e:?}",
                            from.ip()
                        );
                    }
                }
            }
        }
    }
}

// Helper to create a new worker for a specific IP.
fn create_communication_worker(from: IpAddr) -> Sender<Vec<u8>> {
    let (rx_packet_sender, rx_packet_recv) = channel(10);
    tokio::spawn(communication_worker(from, rx_packet_recv));
    rx_packet_sender
}

/// Global state of the active API clients for use by public API.
pub(crate) static API_CLIENTS: Lazy<RwLock<FxHashMap<IpAddr, HostClient<FatalError>>>> =
    Lazy::new(|| {
        RwLock::new({
            let mut m = FxHashMap::default();
            m.reserve(1000);
            m
        })
    });

/// Global subscription to signal a new connection is available.
pub(crate) static CONNECTION_SUBSCRIBER: Lazy<broadcast::Sender<Connection>> =
    Lazy::new(|| broadcast::channel(1000).0);

/// This handles incoming packets from a specific IP.
async fn communication_worker(ip: IpAddr, packet_recv: Receiver<Vec<u8>>) {
    debug!("{ip}: Registered new connection, starting handshake");

    // TODO: This is where we should perform version checks and firmware update devices before
    // accepting them as active. Most likely they will restart, and this connection will be closed
    // and recreated as soon as the device comes back updated and can pass this check.
    //
    // match firmware_updating::check_version_and_maybe_update(&mut packet_recv) {
    //     FirmwareUpdateStatus::NeedsUpdating => {
    //         debug!("{ip}: Firmware needs updating, performing firmware update");
    //
    //         firmware_updating::start_firmware_update(&ip, packet_recv).await;
    //
    //         // Close the worker and await the reconnection after updates.
    //         return;
    //     }
    //     FirmwareUpdateStatus::Valid => {
    //         debug!("{ip}: Firmware valid, continuing");
    //     }
    // }

    debug!("{ip}: Connection active");

    // 0. Wrap the socket and `packet_recv` with `Endpoint` implementor
    // 1. Do the handshake with open_server
    // 2. Replace socket and `packet_recv` in `plumbing::` with relevant ApplicationDataReceiver/Sender implementors

    let psk = [(
        Identity::from(b"hello world"),
        Key::from(b"11111234567890qwertyuiopasdfghjklzxc"),
    )];

    let server_config = ServerConfig { psk: &psk };

    let buf = &mut vec![0; 16 * 1024];
    let rng = &mut rand::rngs::OsRng;

    let server_socket = edtls::DtlsSocket::new(packet_recv, (ip, 8321));

    let server_connection = open_server(server_socket, &server_config, rng, buf)
        .await
        .unwrap();

    let (tx_sender, mut tx_receiver) = framed_queue(10);
    let (mut rx_sender, rx_receiver) = framed_queue(10);

    let rx = plumbing::UdpDatagramReceiver::new(rx_receiver);
    let tx = plumbing::UdpDatagramSender::new(tx_sender);

    let mut sp = plumbing::Spawner::new();

    // We have one host client per connection.
    let hostclient = HostClient::<FatalError>::new_with_wire(tx, rx, &mut sp, ERROR_PATH, 10);

    let _ = CONNECTION_SUBSCRIBER.send(Connection::New(ip));

    // Store the API client for access by public APIs
    {
        API_CLIENTS.write().await.insert(ip, hostclient);
    }

    let mut rx_buf = vec![0; 1536];
    let mut tx_buf = vec![0; 1536];

    let mut delay = Delay;
    tokio::select! {
        _ = server_connection.run(&mut rx_buf, &mut tx_buf, &mut rx_sender, &mut tx_receiver, &mut delay) => {},
        _ = sp.select_on_all_workers() => {}
    }

    // cleanup of global state
    API_CLIENTS.write().await.remove(&ip);

    let _ = CONNECTION_SUBSCRIBER.send(Connection::Closed(ip));

    debug!("{ip}: Connection dropped");
}

mod edtls {
    use std::{fmt::Debug, net::IpAddr, time::Duration};

    use embedded_dtls::{DelayNs, Endpoint};
    use tokio::{
        sync::{mpsc::Receiver, Mutex},
        time::{error::Elapsed, timeout},
    };

    pub struct Delay;

    impl DelayNs for Delay {
        async fn delay_ns(&mut self, ns: u32) {
            tokio::time::sleep(Duration::from_nanos(ns as _)).await;
        }
    }

    use super::SOCKET;

    pub struct DtlsSocket {
        endpoint: (IpAddr, u16),
        // This is a little unfortunate but for now we roll
        rx: Mutex<Receiver<Vec<u8>>>,
    }

    impl DtlsSocket {
        pub fn new(rx: Receiver<Vec<u8>>, endpoint: (IpAddr, u16)) -> Self {
            Self {
                rx: rx.into(),
                endpoint,
            }
        }
    }
    impl Debug for DtlsSocket {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let (ip, port) = self.endpoint;
            write!(f, "DtlsSocket {{ endpoint: {ip}:{port} }}")
        }
    }

    impl Endpoint for DtlsSocket {
        type SendError = anyhow::Error;

        type ReceiveError = anyhow::Error;

        async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError> {
            let socket = SOCKET
                .get()
                .ok_or_else(|| anyhow::anyhow!("Socket is not initialized"))?;
            socket
                .send_to(buf, self.endpoint)
                .await
                .map_err(|e| anyhow::Error::from(e))?;
            Ok(())
        }

        async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError> {
            match timeout(Duration::from_secs(5), self.rx.lock().await.recv()).await {
                Ok(Some(received_data)) => {
                    let n = received_data.len();
                    if buf.len() < n {
                        return Err(anyhow::anyhow!(
                            "Could not fit the received datagram into the buffer"
                        ));
                    }
                    let buf = &mut buf[..n];
                    buf.copy_from_slice(&received_data);
                    Ok(buf)
                }
                Ok(None) => Err(anyhow::anyhow!("All senders were closed")),
                Err(Elapsed { .. }) => Err(anyhow::anyhow!("Connection timed out")),
            }
        }
    }
}

mod plumbing {
    use core::future::Future;

    use embedded_dtls::{
        queue_helpers::{Receiver, Sender},
        ApplicationDataReceiver, ApplicationDataSender,
    };
    use rpc_definition::postcard_rpc::host_client::{WireRx, WireSpawn, WireTx};
    use tokio::task::JoinSet;

    pub struct UdpDatagramReceiver {
        rx: Receiver,
    }

    impl UdpDatagramReceiver {
        pub fn new(rx: Receiver) -> Self {
            Self { rx }
        }
    }

    #[derive(thiserror::Error, Debug)]
    #[error(transparent)]
    pub struct Error(#[from] anyhow::Error);

    impl WireRx for UdpDatagramReceiver {
        type Error = Error;

        fn receive(&mut self) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
            async {
                let data = Vec::from(
                    self.rx
                        .peek()
                        .await
                        .map_err(|_| anyhow::anyhow!("Channel closed"))?
                        .as_ref(),
                );
                self.rx
                    .pop()
                    .map_err(|_| anyhow::anyhow!("Channel closed"))?;
                Ok(data)
            }
        }
    }

    pub struct UdpDatagramSender {
        tx: Sender,
    }

    impl UdpDatagramSender {
        pub fn new(tx: Sender) -> Self {
            Self { tx }
        }
    }

    impl WireTx for UdpDatagramSender {
        type Error = Error;

        fn send(&mut self, data: Vec<u8>) -> impl Future<Output = Result<(), Self::Error>> + Send {
            async {
                self.tx
                    .send(data)
                    .await
                    .map_err(|_| anyhow::anyhow!("Channel closed"))?;
                Ok(())
            }
        }
    }

    pub struct Spawner {
        handles: JoinSet<()>,
    }

    impl Spawner {
        pub fn new() -> Self {
            Self {
                handles: JoinSet::new(),
            }
        }
        pub async fn select_on_all_workers(mut self) {
            self.handles.join_next().await;
            self.handles.shutdown().await;
        }
    }

    impl WireSpawn for Spawner {
        fn spawn(&mut self, fut: impl Future<Output = ()> + Send + 'static) {
            let _ = self.handles.spawn(fut);
        }
    }
}
