use std::{future::Future, marker::PhantomData, ops::ControlFlow, pin::Pin, sync::Arc};

use ntp_proto::{
    IgnoreReason, NtpClock, NtpHeader, NtpInstant, NtpTimestamp, Peer, PeerSnapshot, ReferenceId,
    SystemConfig, SystemSnapshot,
};
use ntp_udp::UdpSocket;
use rand::{thread_rng, Rng};
use tracing::{debug, instrument, warn};

use tokio::{
    sync::watch,
    time::{Instant, Sleep},
};

use crate::peer_manager::PeerIndex;

/// Trait needed to allow injecting of futures other than tokio::time::Sleep for testing
pub trait Wait: Future<Output = ()> {
    fn reset(self: Pin<&mut Self>, deadline: Instant);
}

impl Wait for Sleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.reset(deadline);
    }
}

/// Only messages from the current reset epoch are valid. The system's reset epoch is incremented
/// (with wrapping addition) on every reset. Only after a reset does the peer update its reset
/// epoch, thereby indicating to the system that the reset was successful and the peer's messages
/// are valid measurements again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResetEpoch(u64);

impl ResetEpoch {
    #[must_use]
    pub const fn inc(mut self) -> Self {
        self.0 = self.0.wrapping_add(1);

        self
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MsgForSystem {
    /// Received a Kiss-o'-Death and must demobilize
    MustDemobilize(PeerIndex),
    /// Received an acceptable packet and made a new peer snapshot
    /// A new measurement should try to trigger a clock select
    NewMeasurement(PeerIndex, ResetEpoch, PeerSnapshot),
    /// A snapshot may have been updated, but this should not
    /// trigger a clock select in System
    UpdatedSnapshot(PeerIndex, ResetEpoch, PeerSnapshot),
}

#[derive(Debug, Clone)]
pub struct PeerChannels {
    pub msg_for_system_sender: tokio::sync::mpsc::Sender<MsgForSystem>,
    pub system_snapshots: Arc<tokio::sync::RwLock<SystemSnapshot>>,
    pub system_config: Arc<tokio::sync::RwLock<SystemConfig>>,
    pub reset: watch::Receiver<ResetEpoch>,
}

impl PeerChannels {
    #[cfg(test)]
    pub fn test() -> Self {
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let (_, rx) = tokio::sync::watch::channel(ResetEpoch::default());
        PeerChannels {
            msg_for_system_sender: tx,
            system_snapshots: Arc::new(tokio::sync::RwLock::new(SystemSnapshot::default())),
            system_config: Arc::new(tokio::sync::RwLock::new(SystemConfig::default())),
            reset: rx,
        }
    }
}

pub(crate) struct PeerTask<C: 'static + NtpClock + Send, T: Wait> {
    _wait: PhantomData<T>,
    index: PeerIndex,
    clock: C,
    socket: UdpSocket,
    channels: PeerChannels,

    peer: Peer,

    // we don't store the real origin timestamp in the packet, because that would leak our
    // system time to the network (and could make attacks easier). So instead there is some
    // garbage data in the origin_timestamp field, and we need to track and pass along the
    // actual origin timestamp ourselves.
    /// Timestamp of the last packet that we sent
    last_send_timestamp: Option<NtpTimestamp>,

    /// Instant last poll message was sent (used for timing the wait)
    last_poll_sent: Instant,

    /// Number of resets that this peer has performed
    reset_epoch: ResetEpoch,
}

impl<C, T> PeerTask<C, T>
where
    C: 'static + NtpClock + Send,
    T: Wait,
{
    /// Set the next deadline for the poll interval based on current state
    fn update_poll_wait(&self, poll_wait: &mut Pin<&mut T>, system_snapshot: SystemSnapshot) {
        let poll_interval = self
            .peer
            .current_poll_interval(system_snapshot)
            .as_system_duration();

        // randomize the poll interval a little to make it harder to predict poll requests
        let poll_interval = poll_interval.mul_f64(thread_rng().gen_range(1.01..=1.05));

        poll_wait
            .as_mut()
            .reset(self.last_poll_sent + poll_interval);
    }

    async fn handle_poll(&mut self, poll_wait: &mut Pin<&mut T>) {
        let system_snapshot = *self.channels.system_snapshots.read().await;
        let packet = self.peer.generate_poll_message(system_snapshot);

        // Sent a poll, so update waiting to match deadline of next
        self.last_poll_sent = Instant::now();
        self.update_poll_wait(poll_wait, system_snapshot);

        // NOTE: fitness check is not performed here, but by System
        let snapshot = PeerSnapshot::from_peer(&self.peer);
        let msg = MsgForSystem::UpdatedSnapshot(self.index, self.reset_epoch, snapshot);
        self.channels.msg_for_system_sender.send(msg).await.ok();

        match self.clock.now() {
            Err(e) => {
                // we cannot determine the origin_timestamp
                panic!("`clock.now()` reported an error: {:?}", e)
            }
            Ok(ts) => {
                self.last_send_timestamp = Some(ts);
            }
        }

        match self.socket.send(&packet.serialize()).await {
            Err(error) => {
                warn!(?error, "poll message could not be sent");
            }
            Ok((_written, opt_send_timestamp)) => {
                // update the last_send_timestamp with the one given by the kernel, if available
                self.last_send_timestamp = opt_send_timestamp.or(self.last_send_timestamp);
            }
        }
    }

    async fn handle_packet(
        &mut self,
        poll_wait: &mut Pin<&mut T>,
        packet: NtpHeader,
        send_timestamp: NtpTimestamp,
        recv_timestamp: NtpTimestamp,
    ) -> ControlFlow<(), ()> {
        let ntp_instant = NtpInstant::now();

        let system_snapshot = *self.channels.system_snapshots.read().await;
        let result = self.peer.handle_incoming(
            system_snapshot,
            packet,
            ntp_instant,
            self.channels.system_config.read().await.frequency_tolerance,
            send_timestamp,
            recv_timestamp,
        );

        // Handle incoming may have changed poll interval based on message, respect that change
        self.update_poll_wait(poll_wait, system_snapshot);

        match result {
            Ok(update) => {
                debug!("packet accepted");

                // NOTE: fitness check is not performed here, but by System

                let msg = MsgForSystem::NewMeasurement(self.index, self.reset_epoch, update);
                self.channels.msg_for_system_sender.send(msg).await.ok();
            }
            Err(IgnoreReason::KissDemobilize) => {
                warn!("Demobilizing peer connection on request of remote.");
                let msg = MsgForSystem::MustDemobilize(self.index);
                self.channels.msg_for_system_sender.send(msg).await.ok();

                return ControlFlow::Break(());
            }
            Err(ignore_reason) => {
                debug!(?ignore_reason, "packet ignored");
            }
        }

        ControlFlow::Continue(())
    }

    async fn run(&mut self, mut poll_wait: Pin<&mut T>) {
        loop {
            let mut buf = [0_u8; 48];

            tokio::select! {
                () = &mut poll_wait => {
                    self.handle_poll(&mut poll_wait).await;
                },
                result = self.channels.reset.changed() => {
                    if let Ok(()) = result {
                        // reset the measurement state (as if this association was just created).
                        // crucially, this sets `self.next_expected_origin = None`, meaning that
                        // in-flight requests are ignored
                        self.peer.reset_measurements();

                        // our next measurement will have the new reset epoch
                        self.reset_epoch = *self.channels.reset.borrow_and_update();
                    }
                }
                result = self.socket.recv(&mut buf) => {
                    let send_timestamp = match self.last_send_timestamp {
                        Some(ts) => ts,
                        None => {
                            warn!("we received a message without having sent one; discarding");
                            continue;
                        }
                    };

                    if let Some((packet, recv_timestamp)) = accept_packet(result, &buf) {
                        match self.handle_packet(&mut poll_wait, packet, send_timestamp, recv_timestamp).await{
                            ControlFlow::Continue(_) => continue,
                            ControlFlow::Break(_) => break,
                        }
                    }
                },
            }
        }
    }
}

impl<C> PeerTask<C, Sleep>
where
    C: 'static + NtpClock + Send,
{
    #[instrument(skip(clock, channels))]
    pub async fn spawn<A>(
        index: PeerIndex,
        addr: A,
        clock: C,
        mut channels: PeerChannels,
    ) -> std::io::Result<tokio::task::JoinHandle<()>>
    where
        A: tokio::net::ToSocketAddrs + std::fmt::Debug,
    {
        let socket = UdpSocket::new("0.0.0.0:0", addr).await?;
        let our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());
        let peer_id = ReferenceId::from_ip(socket.as_ref().peer_addr().unwrap().ip());

        let handle = tokio::spawn(async move {
            let local_clock_time = NtpInstant::now();
            let peer = Peer::new(our_id, peer_id, local_clock_time);

            let poll_wait = tokio::time::sleep(std::time::Duration::default());
            tokio::pin!(poll_wait);

            // Even though we currently always have reset_epoch start at
            // the default value, we shouldn't rely on that.
            let reset_epoch = *channels.reset.borrow_and_update();

            let mut process = PeerTask {
                _wait: PhantomData,
                index,
                clock,
                channels,
                socket,
                peer,
                last_send_timestamp: None,
                last_poll_sent: Instant::now(),
                reset_epoch,
            };

            process.run(poll_wait).await
        });

        Ok(handle)
    }
}

fn accept_packet(
    result: Result<(usize, Option<NtpTimestamp>), std::io::Error>,
    buf: &[u8; 48],
) -> Option<(NtpHeader, NtpTimestamp)> {
    match result {
        Ok((size, Some(recv_timestamp))) => {
            // Note: packets are allowed to be bigger when including extensions.
            // we don't expect them, but the server may still send them. The
            // extra bytes are guaranteed safe to ignore. `recv` truncates the messages.
            // Messages of fewer than 48 bytes are skipped entirely
            if size < 48 {
                warn!(expected = 48, actual = size, "received packet is too small");

                None
            } else {
                match NtpHeader::deserialize(buf) {
                    Ok(packet) => Some((packet, recv_timestamp)),
                    Err(e) => {
                        warn!("received invalid packet: {}", e);
                        None
                    }
                }
            }
        }
        Ok((size, None)) => {
            warn!(?size, "received a packet without a timestamp");

            None
        }
        Err(receive_error) => {
            warn!(?receive_error, "could not receive packet");

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntp_proto::{NtpAssociationMode, NtpDuration, NtpLeapIndicator, PollInterval};
    use tokio::sync::{mpsc, watch, RwLock};

    use super::*;

    struct TestWaitSender {
        state: Arc<std::sync::Mutex<TestWaitState>>,
    }

    impl TestWaitSender {
        fn notify(&self) {
            let mut state = self.state.lock().unwrap();
            state.pending = true;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    struct TestWait {
        state: Arc<std::sync::Mutex<TestWaitState>>,
    }

    struct TestWaitState {
        waker: Option<std::task::Waker>,
        pending: bool,
    }

    impl Future for TestWait {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            let mut state = self.state.lock().unwrap();

            if state.pending {
                state.pending = false;
                state.waker = None;
                std::task::Poll::Ready(())
            } else {
                state.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    impl Wait for TestWait {
        fn reset(self: Pin<&mut Self>, _deadline: Instant) {}
    }

    impl Drop for TestWait {
        fn drop(&mut self) {
            self.state.lock().unwrap().waker = None;
        }
    }

    impl TestWait {
        fn new() -> (TestWait, TestWaitSender) {
            let state = Arc::new(std::sync::Mutex::new(TestWaitState {
                waker: None,
                pending: false,
            }));

            (
                TestWait {
                    state: state.clone(),
                },
                TestWaitSender { state },
            )
        }
    }

    const EPOCH_OFFSET: u32 = (70 * 365 + 17) * 86400;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::time::SystemTimeError;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            let cur =
                std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;

            Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
                EPOCH_OFFSET.wrapping_add(cur.as_secs() as u32),
                cur.subsec_nanos(),
            ))
        }

        fn set_freq(&self, _freq: f64) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }

        fn update_clock(
            &self,
            _offset: NtpDuration,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
            _poll_interval: PollInterval,
            _leap_status: NtpLeapIndicator,
        ) -> Result<(), Self::Error> {
            panic!("Shouldn't be called by peer");
        }
    }

    async fn test_startup<T: Wait>(
        port_base: u16,
    ) -> (
        PeerTask<TestClock, T>,
        UdpSocket,
        mpsc::Receiver<MsgForSystem>,
        watch::Sender<ResetEpoch>,
    ) {
        // Note: Ports must be unique among tests to deal with parallelism, hence
        // port_base
        let socket = UdpSocket::new(
            format!("127.0.0.1:{}", port_base),
            format!("127.0.0.1:{}", port_base + 1),
        )
        .await
        .unwrap();
        let test_socket = UdpSocket::new(
            format!("127.0.0.1:{}", port_base + 1),
            format!("127.0.0.1:{}", port_base),
        )
        .await
        .unwrap();
        let our_id = ReferenceId::from_ip(socket.as_ref().local_addr().unwrap().ip());
        let peer_id = ReferenceId::from_ip(socket.as_ref().peer_addr().unwrap().ip());

        let local_clock_time = NtpInstant::now();
        let peer = Peer::new(our_id, peer_id, local_clock_time);

        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let system_config = Arc::new(RwLock::new(SystemConfig::default()));
        let (msg_for_system_sender, msg_for_system_receiver) = mpsc::channel(1);
        let (reset_send, reset) = watch::channel(ResetEpoch::default());

        let process = PeerTask {
            _wait: PhantomData,
            index: PeerIndex::from_inner(0),
            clock: TestClock {},
            channels: PeerChannels {
                msg_for_system_sender,
                system_snapshots,
                system_config,
                reset,
            },
            socket,
            peer,
            last_send_timestamp: None,
            last_poll_sent: Instant::now(),
            reset_epoch: ResetEpoch::default(),
        };

        (process, test_socket, msg_for_system_receiver, reset_send)
    }

    #[tokio::test]
    async fn test_spawn_reset_epoch() {
        // Note: Ports must be unique among tests to deal with parallelism
        let _recv_socket = UdpSocket::new("127.0.0.1:8003", "127.0.0.1:8002")
            .await
            .unwrap();

        let epoch = ResetEpoch::default().inc();
        let system_snapshots = Arc::new(RwLock::new(SystemSnapshot::default()));
        let system_config = Arc::new(RwLock::new(SystemConfig::default()));
        let (msg_for_system_sender, mut msg_for_system_receiver) = mpsc::channel(1);
        let (_reset_send, reset) = watch::channel(epoch);

        let handle = PeerTask::spawn(
            PeerIndex::from_inner(0),
            "127.0.0.1:8003",
            TestClock {},
            PeerChannels {
                msg_for_system_sender,
                system_snapshots,
                system_config,
                reset,
            },
        )
        .await
        .unwrap();

        let peer_epoch = match msg_for_system_receiver.recv().await.unwrap() {
            MsgForSystem::UpdatedSnapshot(_, peer_epoch, _) => peer_epoch,
            _ => panic!("Unexpected message"),
        };

        assert_eq!(epoch, peer_epoch);

        handle.abort();
    }

    #[tokio::test]
    async fn test_poll_sends_state_update_and_packet() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, socket, mut msg_recv, _reset) = test_startup(8004).await;

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::UpdatedSnapshot(_, _, _)));

        let mut buf = [0; 48];
        let network = socket.recv(&mut buf).await.unwrap();
        assert_eq!(network.0, 48);

        handle.abort();
    }

    #[tokio::test]
    async fn test_reset_updates_epoch() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, _socket, mut msg_recv, reset) = test_startup(8006).await;

        let epoch_a = ResetEpoch::default();
        let epoch_b = epoch_a.inc();

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();
        let peer_epoch = match msg_recv.recv().await.unwrap() {
            MsgForSystem::UpdatedSnapshot(_, peer_epoch, _) => peer_epoch,
            _ => panic!("Unexpected message"),
        };
        assert_eq!(peer_epoch, epoch_a);

        reset.send(epoch_b).unwrap();

        // Not foolproof, but hopefully this ensures the reset is processed first
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        poll_send.notify();
        let peer_epoch = match msg_recv.recv().await.unwrap() {
            MsgForSystem::UpdatedSnapshot(_, peer_epoch, _) => peer_epoch,
            _ => panic!("Unexpected message"),
        };
        assert_eq!(peer_epoch, epoch_b);

        handle.abort();
    }

    #[tokio::test]
    async fn test_timeroundtrip() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, socket, mut msg_recv, _reset) = test_startup(8008).await;

        let (poll_wait, poll_send) = TestWait::new();
        let clock = TestClock {};

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::UpdatedSnapshot(_, _, _)));

        let mut buf = [0; 48];
        let (size, timestamp) = socket.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        let timestamp = timestamp.unwrap();

        let rec_packet = NtpHeader::deserialize(&buf).unwrap();
        let mut send_packet = NtpHeader::new();
        send_packet.leap = NtpLeapIndicator::NoWarning;
        send_packet.stratum = 1;
        send_packet.mode = NtpAssociationMode::Server;
        send_packet.origin_timestamp = rec_packet.transmit_timestamp;
        send_packet.receive_timestamp = timestamp;
        send_packet.transmit_timestamp = clock.now().unwrap();

        socket.send(&send_packet.serialize()).await.unwrap();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::NewMeasurement(_, _, _)));

        handle.abort();
    }

    #[tokio::test]
    async fn test_deny_stops_poll() {
        // Note: Ports must be unique among tests to deal with parallelism
        let (mut process, socket, mut msg_recv, _reset) = test_startup(8010).await;

        let (poll_wait, poll_send) = TestWait::new();

        let handle = tokio::spawn(async move {
            tokio::pin!(poll_wait);
            process.run(poll_wait).await;
        });

        poll_send.notify();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::UpdatedSnapshot(_, _, _)));

        let mut buf = [0; 48];
        let (size, timestamp) = socket.recv(&mut buf).await.unwrap();
        assert_eq!(size, 48);
        assert!(timestamp.is_some());

        let rec_packet = NtpHeader::deserialize(&buf).unwrap();
        let mut send_packet = NtpHeader::new();
        send_packet.stratum = 0;
        send_packet.mode = NtpAssociationMode::Server;
        send_packet.origin_timestamp = rec_packet.transmit_timestamp;
        send_packet.reference_id = ReferenceId::KISS_DENY;

        socket.send(&send_packet.serialize()).await.unwrap();

        let msg = msg_recv.recv().await.unwrap();
        assert!(matches!(msg, MsgForSystem::MustDemobilize(_)));

        poll_send.notify();

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {/*expected */},
            _ = socket.recv(&mut buf) => { assert!(false); }
        }

        handle.abort();
    }
}
