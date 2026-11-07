//! A background worker that keeps many of the server's one-sided RMAs in flight at once.
//!
//! libfabric RMA is asynchronous: posting a `fi_writemsg`/`fi_read` returns immediately and the
//! completion arrives later on the completion queue. `FabricService` exploits that with one
//! event-loop thread over one endpoint: it drains submitted [`TransferRequest`]s, posts up to an
//! in-flight cap without waiting, reaps completions in batches, and dispatches each by its
//! `op_context`, the per-op heap pointer that identifies which transfer completed.
//!
//! Completions go back to the caller in batches via the `complete_batch` hook, so a whole batch
//! finishes under one lock acquisition rather than one per op.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;

use dma_libfabric_protocol::DmaError;

use crate::configuration::Configuration;
use crate::memory_region::MemoryRegion;
use crate::operands::Operands;
use crate::pool::Pool;
use crate::reply::{Answer, reply};

/// Direction of the one-sided RMA the server initiates against the client's exposed buffer.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// `fi_writemsg` local to peer: the `dma.get` path, sending [`Operands::source`].
    ToPeer,
    /// `fi_read` peer to local: the `dma.set` path, putting `length` bytes in
    /// [`Operands::allocate`]. The peer's advertisement says how many bytes there are to read.
    FromPeer {
        /// Transfer reads this many bytes from the peer.
        length: usize,
    },
}

/// The result of a completed transfer
#[derive(Debug, Clone, Copy)]
pub struct TransferDone {
    /// how many bytes transferred
    pub bytes: usize,
    /// CRC32C, if requested
    pub checksum: Option<u32>,
}

/// The outcome of a transfer the worker hands back.
pub type Outcome = Result<TransferDone, DmaError>;

/// A finished transfer's caller-supplied context paired with its outcome.
pub struct Completion<T> {
    /// caller-supplied context
    pub caller_context: T,
    /// Transfer disposition
    pub outcome: Outcome,
}

/// Hook the caller supplies to finish a batch of completions under one lock acquisition. The
/// context `T` is opaque here; it carries whatever the caller needs to reply and commit.
pub type BatchCompleter<T> = Box<dyn Fn(std::vec::Drain<Completion<T>>) + Send + Sync>;

/// A submitted transfer: Where the peer's exposed buffer is, which way the bytes go, and a
/// `caller_context` that supplies the local operand and is handed back when the RMA finishes.
pub struct TransferRequest<TContext> {
    /// Your identifier for the peer. The worker caches its address-vector entry under it until
    /// [`FabricService::remove_peer`], so use one id per connected client.
    pub client_id: u64,
    /// The peer's fabric address, from its [`Advertisement`](dma_libfabric_protocol::Advertisement).
    /// Inserted into the address vector on first use for `client_id`.
    pub peer_address: Vec<u8>,
    /// The rkey of the peer's exposed buffer.
    pub remote_key: u64,
    /// The peer's buffer as the provider addresses it: a virtual address under `FI_MR_VIRT_ADDR`
    /// (efa), otherwise an offset (tcp).
    pub remote_address: u64,
    /// Which way the bytes go, and for [`Direction::FromPeer`], how many.
    pub direction: Direction,
    /// Compute a CRC-32c of the payload, off the fabric worker, into [`TransferDone::checksum`].
    pub want_checksum: bool,
    /// Supplies the local [`Operands`] and comes back to you in the [`Completion`].
    pub caller_context: TContext,
    /// The caller's per-transfer span. A plain `Id`, not a `Span` clone, because `tracing-cache`
    /// closes a span on the first clone's drop — so the worker parents the on-wire span under it
    /// without touching its lifetime, while the one owning `Span` rides in `caller_context` and
    /// closes at completion. `None` when tracing is off.
    pub parent_id: Option<tracing::span::Id>,
}

/// What the worker consumes off its channel: a transfer to run, or a request to drop a disconnected
/// client's address-vector entry. One ordered channel carries both, so a removal is processed after
/// every transfer the client already submitted.
pub enum WorkerMessage<TContext> {
    Transfer(TransferRequest<TContext>),
    /// Insert a client's peer address ahead of its first transfer, answering on `reply`, so the
    /// caller's hello can fail if the address is unusable rather than its first transfer.
    AddPeer {
        client_id: u64,
        address: Vec<u8>,
        reply: Answer<Result<(), DmaError>>,
    },
    /// Remove this disconnected client's peer once its in-flight transfers have drained.
    RemovePeer(u64),
    /// Register a caller-owned span on this worker's domain, answering on `reply`. This keeps
    /// domain calls on the worker thread who owns it.
    Register {
        base: usize,
        length: usize,
        reply: Answer<Result<(), DmaError>>,
    },
}

/// Information sent from the worker thread when the endpoint is ready.
#[derive(Debug, Clone)]
pub(crate) struct EndpointReadyInfo {
    /// The endpoint's fabric address.
    pub address: Vec<u8>,
    /// Ack buffer descriptor for client acknowledgements, if available.
    pub ack_buffer: Option<crate::endpoint::AckBufferInfo>,
}

/// A sideband an rpc server uses to implement data-transfer commands over a faster transport. It
/// does no rpc of its own.
///
/// Owns the `fabric-nn` worker thread and the submission channel. Dropping the server closes the
/// channel, so the worker drains its in-flight ops, exits, and is joined.
pub struct FabricService<TContext: Send + 'static> {
    sender: Option<Sender<WorkerMessage<TContext>>>,
    dma_worker_handle: Option<JoinHandle<()>>,
    /// The worker endpoint's fabric address, captured at startup. `efa-direct` requires the target
    /// hold the initiator's address, so a client inserts this into its own address vector before the
    /// server RMAs against it, learning it via [`Self::local_address`] in the `dma.hello` exchange.
    address: Vec<u8>,
    /// Ack buffer descriptor for client acknowledgements.
    ack_buffer: Option<crate::endpoint::AckBufferInfo>,
    /// Submitted but not yet finished, counting queued ops as well as posted ones so the depth of
    /// this device's backlog is visible to a caller balancing across devices. Shared with the worker,
    /// which decrements as each op finishes.
    outstanding: Arc<AtomicUsize>,
}

impl<TContext: Send + 'static> std::fmt::Debug for FabricService<TContext> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FabricService")
            .field("running", &self.sender.is_some())
            .finish()
    }
}

impl<TContext: Send + 'static> FabricService<TContext> {
    /// Open the server endpoint on a worker thread and start serving transfers, blocking until the
    /// endpoint opens or fails to. Completions run on the worker thread, except checksummed ones,
    /// whose CRC and reply run on the shared `pool`.
    pub fn start(
        configuration: &Configuration,
        complete_batch: BatchCompleter<TContext>,
        pool: Arc<Pool>,
    ) -> Result<Self, DmaError>
    where
        TContext: Operands,
    {
        let (sender, receiver) = channel();
        let (ready_answer, ready) = reply();
        let configuration = configuration.clone();
        // Shared with the pool jobs finishing checksummed transfers off the worker thread.
        let complete_batch = Arc::new(complete_batch);
        let outstanding = Arc::new(AtomicUsize::new(0));
        let worker_outstanding = Arc::clone(&outstanding);

        static INDEX: AtomicUsize = AtomicUsize::new(0);
        let handle = std::thread::Builder::new()
            .name(format!(
                "fabric-{:02}",
                INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ))
            .spawn(move || {
                crate::server_dma_worker::worker_main(
                    configuration,
                    ready_answer,
                    &receiver,
                    complete_batch,
                    pool,
                    &worker_outstanding,
                )
            })
            .map_err(|error| DmaError::Fabric(format!("failed to spawn fabric worker: {error}")))?;
        match ready.wait() {
            Some(Ok(info)) => Ok(Self {
                sender: Some(sender),
                dma_worker_handle: Some(handle),
                address: info.address,
                ack_buffer: info.ack_buffer,
                outstanding,
            }),
            Some(Err(error)) => {
                let _ = handle.join();
                Err(error)
            }
            None => Err(DmaError::Fabric(
                "fabric worker exited before signalling readiness".into(),
            )),
        }
    }

    /// The worker endpoint's fabric address, which a client discovers via `dma.hello` before the
    /// server RMAs against it: on efa-direct the target must hold the initiator's address in its
    /// address vector. This side initiates every dma itself.
    pub fn local_address(&self) -> &[u8] {
        &self.address
    }

    /// The ack buffer descriptor clients use to send acknowledgements back to this server.
    /// Returns `None` if ack buffer registration failed.
    pub fn ack_buffer_info(&self) -> Option<crate::endpoint::AckBufferInfo> {
        self.ack_buffer
    }

    /// Transfers submitted here but not yet finished, queued and posted alike. The load signal a
    /// caller balances on: it rises the moment work is handed over, not when it reaches the wire.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Relaxed)
    }

    /// Submit a transfer, whose completion is handed back in a batch when it finishes. If the worker
    /// is gone the request comes back, so the caller can fail the client.
    pub fn submit(
        &self,
        request: TransferRequest<TContext>,
    ) -> Result<(), TransferRequest<TContext>> {
        let Some(sender) = self.sender.as_ref() else {
            return Err(request);
        };
        self.outstanding.fetch_add(1, Ordering::Relaxed);
        sender
            .send(WorkerMessage::Transfer(request))
            .map_err(|error| {
                self.outstanding.fetch_sub(1, Ordering::Relaxed);
                let WorkerMessage::Transfer(request) = error.0 else {
                    unreachable!("sent a Transfer");
                };
                request
            })
    }

    /// Register `storage`, blocking until it is resident.
    ///
    /// Transfers submitted to this server whose operands live in `storage` skip `fi_mr_reg`.
    /// Submitting them to a different server still works. However that server's domain has no
    /// registration covering them, so it takes one per operation. It's slower that way.
    ///
    /// Registering the same storage on several servers pins the span once per device against
    /// `RLIMIT_MEMLOCK`, so prefer one region per device and route its traffic to that server.
    pub fn register<S>(&self, storage: S) -> Result<MemoryRegion<S>, DmaError>
    where
        S: AsRef<[u8]> + Send + Sync + 'static,
    {
        // Boxed before the span is taken. We're playing with pointers so memory position is
        // relevant, and has to stay fixed.
        let storage = Box::new(storage);
        let bytes: &[u8] = (*storage).as_ref();
        let (base, length) = (bytes.as_ptr() as usize, bytes.len());
        if 0 == length {
            return Err(DmaError::Fabric("cannot register 0 bytes".into()));
        }
        let end = base
            .checked_add(length)
            .ok_or_else(|| DmaError::Fabric("registered region range overflows".into()))?;

        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| DmaError::Fabric("fabric worker is gone".into()))?;
        let (answer, waiting) = reply();
        sender
            .send(WorkerMessage::Register {
                base,
                length,
                reply: answer,
            })
            .map_err(|_| DmaError::Fabric("fabric worker is gone".into()))?;
        waiting
            .wait()
            .ok_or_else(|| DmaError::Fabric("fabric worker exited before registering".into()))??;
        Ok(MemoryRegion::new(storage, base, end))
    }

    /// Insert `address` into this endpoint's address vector for `client_id`.
    pub fn add_peer(&self, client_id: u64, address: &[u8]) -> Result<(), DmaError> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| DmaError::Fabric("fabric worker is gone".into()))?;
        let (answer, waiting) = reply();
        sender
            .send(WorkerMessage::AddPeer {
                client_id,
                address: address.to_vec(),
                reply: answer,
            })
            .map_err(|_| DmaError::Fabric("fabric worker is gone".into()))?;
        waiting
            .wait()
            .ok_or_else(|| DmaError::Fabric("fabric worker exited before adding the peer".into()))?
    }

    /// Ask the worker to drop a disconnected client's address-vector entry once its in-flight
    /// transfers drain. Best-effort: if the worker is gone the entry dies with the endpoint.
    pub fn remove_peer(&self, client_id: u64) {
        if let Some(sender) = self.sender.as_ref() {
            let _ = sender.send(WorkerMessage::RemovePeer(client_id));
        }
    }
}

impl<T: Send + 'static> Drop for FabricService<T> {
    fn drop(&mut self) {
        // Closing the channel ends the worker's recv loop.
        self.sender = None;
        if let Some(handle) = self.dma_worker_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{Completion, Direction, FabricService, TransferRequest};
    use crate::configuration::{Configuration, Provider};
    use crate::pool::Pool;

    /// A real tcp server on loopback.
    fn server() -> FabricService<Vec<u8>> {
        let configuration = Configuration {
            providers: vec![Provider::Tcp],
            bind: Some("127.0.0.1".to_string()),
            ..Configuration::default()
        };
        let pool = Arc::new(Pool::new(1).expect("pool"));
        let complete = Box::new(|_: std::vec::Drain<'_, Completion<Vec<u8>>>| {});
        FabricService::start(&configuration, complete, pool).expect("tcp server")
    }

    /// `FI_SOCKADDR_IN` for 127.0.0.1:1, where nothing listens: the tcp provider's connect never
    /// establishes and every post answers `-FI_EAGAIN`.
    const DEAD_PEER: [u8; 16] = [2, 0, 0, 1, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];

    /// The failure this deadline exists to bound: a peer that never connects must fail the
    /// transfer instead of leaving it, and its caller, waiting forever.
    #[test]
    fn a_transfer_to_a_dead_peer_fails_at_the_progress_deadline() {
        let configuration = Configuration {
            providers: vec![Provider::Tcp],
            bind: Some("127.0.0.1".to_string()),
            progress_deadline: Duration::from_millis(50),
            ..Configuration::default()
        };
        let pool = Arc::new(Pool::new(1).expect("pool"));
        let (report, outcomes) = std::sync::mpsc::channel();
        let complete = Box::new(move |batch: std::vec::Drain<'_, Completion<Vec<u8>>>| {
            for completion in batch {
                let _ = report.send(completion.outcome);
            }
        });
        let server = FabricService::start(&configuration, complete, pool).expect("tcp server");

        let request = TransferRequest {
            client_id: 1,
            peer_address: DEAD_PEER.to_vec(),
            remote_key: 0,
            remote_address: 0,
            direction: Direction::ToPeer,
            want_checksum: false,
            caller_context: vec![0xab; 64],
            parent_id: None,
        };
        assert!(server.submit(request).is_ok());

        let outcome = outcomes
            .recv_timeout(Duration::from_secs(5))
            .expect("a completion within the deadline, not a hang");
        assert!(outcome.is_err(), "a dead peer must fail, got {outcome:?}");
    }

    /// A hello inserts the peer with no transfer in sight, and asking again for the same address
    /// shares the entry rather than failing or duplicating it.
    #[test]
    fn add_peer_inserts_ahead_of_any_transfer() {
        let server = server();
        let address = server.local_address().to_vec();
        server.add_peer(1, &address).expect("first insert");
        server.add_peer(1, &address).expect("same address again");
        server.remove_peer(1);
    }
}
