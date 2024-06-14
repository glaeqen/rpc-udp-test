//! The engine drives all communication.
//!
//! Note: This app IP as identifier for each device. You should not do that when running UDP
//! unless you have authentication on the packets, as UDP source addresses are trivial to spoof.

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

    // TODO: This is where we should perform ECDH handshake & authenticity verification of a device.
    //
    // let secure_channel = match secure_channel::perform_handshake(ip, packet_recv).await {
    //     Ok(ch) => ch,
    //     Err(e) => {
    //         error!("{ip}: Failed handshake, error = {e:?}");
    //         return;
    //     }
    // };

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

    let rx = plumbing::UdpDatagramReceiver::new(packet_recv);

    let tx = plumbing::UdpDatagramSender::new(ip);

    let mut sp = plumbing::Spawner::new();

    // We have one host client per connection.
    let hostclient = HostClient::<FatalError>::new_with_wire(tx, rx, &mut sp, ERROR_PATH, 10);

    let _ = CONNECTION_SUBSCRIBER.send(Connection::New(ip));

    // Store the API client for access by public APIs
    {
        API_CLIENTS.write().await.insert(ip, hostclient);
    }

    sp.select_on_all_workers().await;

    let _ = CONNECTION_SUBSCRIBER.send(Connection::Closed(ip));

    // cleanup of global state
    API_CLIENTS.write().await.remove(&ip);

    debug!("{ip}: Connection dropped");
}

mod plumbing {
    use core::future::Future;
    use std::{net::IpAddr, time::Duration};

    use rpc_definition::postcard_rpc::host_client::{WireRx, WireSpawn, WireTx};
    use tokio::{sync::mpsc::Receiver, task::JoinSet, time::timeout};

    use super::SOCKET;

    pub struct UdpDatagramReceiver {
        receiver: Receiver<Vec<u8>>,
    }

    impl UdpDatagramReceiver {
        pub fn new(receiver: Receiver<Vec<u8>>) -> Self {
            Self { receiver }
        }
    }

    #[derive(thiserror::Error, Debug)]
    #[error(transparent)]
    pub struct Error(#[from] anyhow::Error);

    impl WireRx for UdpDatagramReceiver {
        type Error = Error;

        fn receive(&mut self) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
            async {
                match timeout(Duration::from_secs(5), self.receiver.recv()).await {
                    Ok(maybe_data) => Ok(maybe_data.ok_or_else(|| {
                        log::error!("All senders were closed");
                        anyhow::anyhow!("All senders were closed")
                    })?),
                    Err(Elapsed) => {
                        log::info!("Connection timed out");
                        Err(anyhow::anyhow!("Connection timed out").into())
                    }
                }
            }
        }
    }

    pub struct UdpDatagramSender {
        ip: IpAddr,
    }

    impl UdpDatagramSender {
        pub fn new(ip: IpAddr) -> Self {
            Self { ip }
        }
    }

    impl WireTx for UdpDatagramSender {
        type Error = Error;

        fn send(&mut self, data: Vec<u8>) -> impl Future<Output = Result<(), Self::Error>> + Send {
            async move {
                let socket = SOCKET.get().ok_or_else(|| {
                    log::error!("Socket is not initialized");
                    anyhow::anyhow!("Socket is not initialized")
                })?;
                socket
                    .send_to(&data, (self.ip, 8321))
                    .await
                    .map_err(|e| anyhow::Error::from(e))?;
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
