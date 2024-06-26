use crate::app;
use embassy_futures::join::join;
use embassy_net::{
    udp::{PacketMetadata, UdpSocket},
    Ipv4Address,
};
use embedded_dtls::{
    cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
    client::{config::ClientConfig, open_client},
    handshake::extensions::Psk,
    queue_helpers::FramedQueue,
    Endpoint,
};
use heapless::Vec;
use rpc_definition::endpoints::sleep::Sleep;
use rtic_sync::channel::{Receiver, Sender};

// Backend IP.
const BACKEND_ENDPOINT: (Ipv4Address, u16) = (Ipv4Address::new(192, 168, 0, 220), 8321);

/// Main UDP RX/TX data pump. Also sets up the UDP socket.
pub async fn run_comms(
    cx: app::run_comms::Context<'_>,
    mut ethernet_tx_receiver: Receiver<'static, Vec<u8, 128>, 1>,
    mut ethernet_tx_sender: Sender<'static, Vec<u8, 128>, 1>,
    mut sleep_command_sender: Sender<'static, (u32, Sleep), 8>,
) -> ! {
    let stack = *cx.shared.network_stack;
    let rng = cx.local.rng;

    // Ensure DHCP configuration is up before trying connect
    stack.wait_config_up().await;

    defmt::info!("Network task initialized");

    // Then we can use it!
    let mut rx_buffer = [0; 1024];
    let mut tx_buffer = [0; 1024];
    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];

    let mut buf = [0; 1024];

    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket.bind(8321).unwrap();
    let mut fq = FramedQueue::<1024>::new();
    let (s, r) = fq.split().unwrap();

    let c = edtls::DtlsConnectionHandle::new(&socket, BACKEND_ENDPOINT);
    let client_config = ClientConfig {
        psk: Psk {
            identity: b"hello world",
            key: b"11111234567890qwertyuiopasdfghjklzxc",
        },
    };

    let cipher = ChaCha20Poly1305Cipher::default();
    let client_connection = open_client::<_, _, DtlsEcdhePskWithChacha20Poly1305Sha256>(
        &mut rng,
        client_buf,
        client_socket,
        cipher,
        &client_config,
    )
    .await
    .unwrap();

    join(
        async {
            // Send worker.
            loop {
                socket
                    .send_to(
                        &ethernet_tx_receiver.recv().await.unwrap(),
                        BACKEND_ENDPOINT,
                    )
                    .await
                    .unwrap();
            }
        },
        async {
            // Receive worker.
            loop {
                if let Ok((n, _ep)) = socket.recv_from(&mut buf).await {
                    crate::command_handling::dispatch(
                        &buf[..n],
                        &mut ethernet_tx_sender,
                        &mut sleep_command_sender,
                    )
                    .await;
                } else {
                    defmt::error!("UDP: incoming packet truncated");
                }
            }
        },
    )
    .await
    .0
}

/// `embassy-net` stack poller.
pub async fn handle_stack(cx: app::handle_stack::Context<'_>) -> ! {
    cx.shared.network_stack.run().await
}

pub mod edtls {
    use embassy_net::{udp::UdpSocket, IpEndpoint};
    use embedded_dtls::Endpoint;

    pub struct DtlsConnectionHandle<'stack, 'socket> {
        inner: &'socket UdpSocket<'stack>,
        endpoint: IpEndpoint,
    }

    impl<'stack, 'socket> DtlsConnectionHandle<'stack, 'socket> {
        pub fn new(inner: &'socket UdpSocket<'stack>, endpoint: impl Into<IpEndpoint>) -> Self {
            let endpoint = endpoint.into();
            Self { inner, endpoint }
        }
    }

    impl<'stack, 'socket> defmt::Format for DtlsConnectionHandle<'stack, 'socket> {
        fn format(&self, fmt: defmt::Formatter) {
            defmt::write!(
                fmt,
                "DtlsConnectionHandle {{ endpoint: {} }}",
                self.endpoint
            )
        }
    }

    #[derive(defmt::Format)]
    pub enum RecvError {
        UnexpectedSender(IpEndpoint),
        Inner(embassy_net::udp::RecvError),
    }

    impl From<embassy_net::udp::RecvError> for RecvError {
        fn from(value: embassy_net::udp::RecvError) -> Self {
            Self::Inner(value)
        }
    }

    impl<'stack, 'socket> Endpoint for DtlsConnectionHandle<'stack, 'socket> {
        type SendError = embassy_net::udp::SendError;

        type ReceiveError = RecvError;

        async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError> {
            self.inner.send_to(buf, self.endpoint).await
        }

        async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError> {
            let (n, sender_ep) = self.inner.recv_from(buf).await?;
            if self.endpoint != sender_ep {
                return Err(RecvError::UnexpectedSender(sender_ep));
            }
            Ok(&mut buf[..n])
        }
    }
}
