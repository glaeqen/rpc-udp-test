use crate::app;
use embassy_futures::join::join;
use embassy_net::{
    udp::{PacketMetadata, UdpSocket},
    Ipv4Address,
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
