use std::{collections::HashMap, sync::Arc};

use crate::{
    config::PeerConfig,
    observer::ObservablePeerState,
    peer::{MsgForSystem, PeerChannels, PeerTask, ResetEpoch},
};
use ntp_proto::{NtpClock, PeerSnapshot};
use tokio::task::JoinHandle;

const NETWORK_WAIT_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
pub enum PeerStatus {
    /// We are waiting for the first snapshot from this peer _in the current reset epoch_.
    /// This state is the initial state for all peers (when the system is spawned), and also
    /// entered when the system performs a clock jump and forces all peers to reset, or when a peer
    /// indicates that it is no longer fit for synchronization (e.g. root distance became too big)
    ///
    /// A peer can leave this state by either becoming demobilized, or by sending a snapshot that
    /// is within the system's current reset epoch.
    NoMeasurement,
    /// This peer has sent snapshots taken in the current reset epoch. We store the most recent one
    Measurement(PeerSnapshot),
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PeerIndex {
    index: usize,
}

impl PeerIndex {
    #[cfg(test)]
    pub fn from_inner(index: usize) -> Self {
        PeerIndex { index }
    }
}

#[derive(Debug, Default)]
struct PeerIndexIssuer {
    next: usize,
}

impl PeerIndexIssuer {
    fn get(&mut self) -> PeerIndex {
        let index = self.next;
        self.next += 1;
        PeerIndex { index }
    }
}

#[derive(Debug)]
struct PeerData {
    status: PeerStatus,
    config: Arc<PeerConfig>,
}

#[derive(Debug)]
pub struct Peers<C: NtpClock> {
    peers: HashMap<PeerIndex, PeerData>,
    indexer: PeerIndexIssuer,

    channels: PeerChannels,
    clock: C,
}

impl<C: NtpClock> Peers<C> {
    pub fn new(channels: PeerChannels, clock: C) -> Self {
        Peers {
            peers: Default::default(),
            indexer: Default::default(),
            channels,
            clock,
        }
    }

    fn add_peer_internal(&mut self, config: Arc<PeerConfig>) -> JoinHandle<()> {
        let index = self.indexer.get();
        let addr = config.addr.clone();
        self.peers.insert(
            index,
            PeerData {
                status: PeerStatus::NoMeasurement,
                config,
            },
        );
        PeerTask::spawn(
            index,
            addr,
            self.clock.clone(),
            NETWORK_WAIT_PERIOD,
            self.channels.clone(),
        )
    }

    pub async fn add_peer(&mut self, config: PeerConfig) -> JoinHandle<()> {
        self.add_peer_internal(Arc::new(config))
    }

    #[cfg(test)]
    pub fn from_statuslist(data: &[PeerStatus], raw_configs: &[PeerConfig], clock: C) -> Self {
        assert_eq!(data.len(), raw_configs.len());

        let mut peers = HashMap::new();
        let mut indexer = PeerIndexIssuer::default();

        for (i, status) in data.iter().enumerate() {
            let index = indexer.get();
            peers.insert(
                index,
                PeerData {
                    status: status.to_owned(),
                    config: Arc::new(raw_configs[i].clone()),
                },
            );
        }

        Self {
            peers,
            indexer,
            channels: PeerChannels::test(),
            clock,
        }
    }

    pub fn size(&self) -> usize {
        self.peers.len()
    }

    pub fn observe(&self) -> impl Iterator<Item = ObservablePeerState> + '_ {
        self.peers.iter().map(|(_, data)| match data.status {
            PeerStatus::NoMeasurement => ObservablePeerState::Nothing,
            PeerStatus::Measurement(snapshot) => ObservablePeerState::Observable {
                statistics: snapshot.statistics,
                reachability: snapshot.reach,
                uptime: snapshot.time.elapsed(),
                poll_interval: snapshot.poll_interval.as_system_duration(),
                peer_id: snapshot.peer_id,
                address: data.config.addr.to_owned(),
            },
        })
    }

    pub fn valid_snapshots(&self) -> impl Iterator<Item = PeerSnapshot> + '_ {
        self.peers.iter().filter_map(|(_, data)| match data.status {
            PeerStatus::NoMeasurement => None,
            PeerStatus::Measurement(snapshot) => Some(snapshot),
        })
    }

    pub fn update(&mut self, msg: MsgForSystem, current_reset_epoch: ResetEpoch) {
        match msg {
            MsgForSystem::MustDemobilize(index) => {
                self.peers.remove(&index);
            }
            MsgForSystem::NewMeasurement(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                }
            }
            MsgForSystem::UpdatedSnapshot(index, msg_reset_epoch, snapshot) => {
                if current_reset_epoch == msg_reset_epoch {
                    self.peers.get_mut(&index).unwrap().status = PeerStatus::Measurement(snapshot);
                }
            }
            MsgForSystem::NetworkIssue(index) => {
                // Restart the peer reusing its configuration.
                let config = self.peers.remove(&index).unwrap().config;
                self.add_peer_internal(config);
            }
        }
    }

    pub fn reset_all(&mut self) {
        for (_, data) in self.peers.iter_mut() {
            data.status = PeerStatus::NoMeasurement;
        }
    }
}

#[cfg(test)]
mod tests {
    use ntp_proto::{
        peer_snapshot, NtpDuration, NtpInstant, NtpLeapIndicator, NtpTimestamp, PeerStatistics,
        PollInterval,
    };

    use crate::config::PeerHostMode;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct TestClock {}

    impl NtpClock for TestClock {
        type Error = std::io::Error;

        fn now(&self) -> std::result::Result<NtpTimestamp, Self::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn set_freq(&self, _freq: f64) -> Result<(), Self::Error> {
            Ok(())
        }

        fn step_clock(&self, _offset: NtpDuration) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_clock(
            &self,
            _offset: NtpDuration,
            _est_error: NtpDuration,
            _max_error: NtpDuration,
            _poll_interval: PollInterval,
            _leap_status: NtpLeapIndicator,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_peers() {
        let base = NtpInstant::now();
        let prev_epoch = ResetEpoch::default();
        let epoch = prev_epoch.inc();
        let mut peers = Peers::from_statuslist(
            &[PeerStatus::NoMeasurement; 4],
            &(0..4)
                .map(|i| PeerConfig {
                    addr: format!("127.0.0.{i}:123"),
                    mode: PeerHostMode::Server,
                })
                .collect::<Vec<_>>(),
            TestClock {},
        );
        assert_eq!(peers.valid_snapshots().count(), 0);

        peers.update(
            MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                prev_epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    base,
                    NtpDuration::from_seconds(0.1),
                    NtpDuration::from_seconds(0.05),
                ),
            ),
            epoch,
        );
        assert_eq!(peers.valid_snapshots().count(), 0);

        peers.update(
            MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    base,
                    NtpDuration::from_seconds(1.0),
                    NtpDuration::from_seconds(2.0),
                ),
            ),
            epoch,
        );
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers.update(
            MsgForSystem::NewMeasurement(
                PeerIndex { index: 0 },
                epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    base,
                    NtpDuration::from_seconds(0.1),
                    NtpDuration::from_seconds(0.05),
                ),
            ),
            epoch,
        );
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers.update(
            MsgForSystem::UpdatedSnapshot(
                PeerIndex { index: 1 },
                epoch,
                peer_snapshot(
                    PeerStatistics {
                        delay: NtpDuration::from_seconds(0.1),
                        offset: NtpDuration::from_seconds(0.),
                        dispersion: NtpDuration::from_seconds(0.05),
                        jitter: 0.05,
                    },
                    base,
                    NtpDuration::from_seconds(0.1),
                    NtpDuration::from_seconds(0.05),
                ),
            ),
            epoch,
        );
        assert_eq!(peers.valid_snapshots().count(), 2);

        peers.update(MsgForSystem::MustDemobilize(PeerIndex { index: 1 }), epoch);
        assert_eq!(peers.valid_snapshots().count(), 1);

        peers.reset_all();
        assert_eq!(peers.valid_snapshots().count(), 0);
    }
}
