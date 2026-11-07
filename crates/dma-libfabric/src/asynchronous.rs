//! `await` a transfer instead of writing a [`crate::BatchCompleter`].
//!
//! A [`Transfer`] is a [`Future`] any executor can poll. See `examples/async_transfer.rs`, which
//! drives one on a `Condvar`.
//!
//! Drop a [`Transfer`] and you abandon the transfer, but you don't own the memory yet. The RMA is
//! already posted and there is no cancelling it. When the completion lands, your context will be
//! dropped, so its `Drop` is what releases the operand. That drop runs on the fabric
//! worker or a pool thread, so it has the same rule as the hooks. It needs to run quickly and not panic.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use dma_libfabric_protocol::DmaError;

use crate::configuration::Configuration;
use crate::memory_region::MemoryRegion;
use crate::operands::Operands;
use crate::pool::Pool;
use crate::server::{
    Completion, Outcome, TransferRequest, {self},
};

struct Cell<TContext> {
    outcome: Option<(Outcome, TContext)>,
    waker: Option<Waker>,
}

impl<TContext> std::fmt::Debug for Cell<TContext> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cell")
            .field("complete", &self.outcome.is_some())
            .field("waiting", &self.waker.is_some())
            .finish()
    }
}

fn lock<TContext>(cell: &Mutex<Cell<TContext>>) -> MutexGuard<'_, Cell<TContext>> {
    cell.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Awaited<TContext> {
    user: TContext,
    cell: Arc<Mutex<Cell<TContext>>>,
}

impl<TContext> std::fmt::Debug for Awaited<TContext> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Awaited").finish_non_exhaustive()
    }
}

impl<TContext: Operands> Operands for Awaited<TContext> {
    /// pass through to user context
    fn source(&self) -> Option<&[u8]> {
        self.user.source()
    }

    /// pass through to user context
    fn allocate(&mut self, length: usize) -> Option<&mut [u8]> {
        self.user.allocate(length)
    }

    fn cacheable_span(&self) -> Option<crate::CacheableSpan> {
        self.user.cacheable_span()
    }
}

/// A submitted transfer. Resolves to the outcome and the context you submitted.
pub struct Transfer<TContext> {
    cell: Arc<Mutex<Cell<TContext>>>,
}

impl<TContext> std::fmt::Debug for Transfer<TContext> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Transfer")
            .field("complete", &lock(&self.cell).outcome.is_some())
            .finish()
    }
}

impl<TContext> Future for Transfer<TContext> {
    type Output = (Outcome, TContext);

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut cell = lock(&self.cell);
        if let Some(finished) = cell.outcome.take() {
            return Poll::Ready(finished);
        }
        if !matches!(&cell.waker, Some(waker) if waker.will_wake(context.waker())) {
            cell.waker = Some(context.waker().clone());
        }
        Poll::Pending
    }
}

impl<TContext> Drop for Transfer<TContext> {
    fn drop(&mut self) {
        // Waking a task that is gone is pointless
        lock(&self.cell).waker = None;
    }
}

/// Hand a completion to its [`Transfer`], or drop context if that transfer was abandoned.
fn deliver<TContext>(completion: Completion<Awaited<TContext>>) {
    let Completion {
        caller_context: Awaited { user, cell },
        outcome,
    } = completion;
    let waker = {
        let mut guard = lock(&cell);
        guard.outcome = Some((outcome, user));
        guard.waker.take()
    };
    // The last `Arc` standing drops the outcome, so this is where an abandoned transfer's context
    // dies. Drop before wake, so a woken task never wins a race for the refcount.
    drop(cell);
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Deliver each completion in the batch
fn complete_batch<TContext>(completions: std::vec::Drain<'_, Completion<Awaited<TContext>>>) {
    for completion in completions {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver(completion)));
    }
}

/// Move a request onto a different context. Used both to wrap on submit and to unwrap the request
/// handed back when the worker is gone.
fn map_context<TOld, TNew>(
    request: TransferRequest<TOld>,
    map: impl FnOnce(TOld) -> TNew,
) -> TransferRequest<TNew> {
    TransferRequest {
        client_id: request.client_id,
        peer_address: request.peer_address,
        remote_key: request.remote_key,
        remote_address: request.remote_address,
        direction: request.direction,
        want_checksum: request.want_checksum,
        caller_context: map(request.caller_context),
        parent_id: request.parent_id,
    }
}

/// A [`crate::FabricService`] that hands back futures. It installs its own completion hook.
#[derive(Debug)]
pub struct FabricService<TContext: Send + 'static> {
    inner: server::FabricService<Awaited<TContext>>,
}

impl<TContext: Operands + Send + 'static> FabricService<TContext> {
    /// Open the endpoint, blocking until it is up or fails.
    pub fn start(configuration: &Configuration, pool: Arc<Pool>) -> Result<Self, DmaError> {
        let inner = server::FabricService::start(configuration, Box::new(complete_batch), pool)?;
        Ok(Self { inner })
    }

    /// Submit a transfer and get the future for its completion. Submission happens inline, so a
    /// request you have not polled yet is still queued and still counted by [`Self::outstanding`].
    pub fn transfer(
        &self,
        request: TransferRequest<TContext>,
    ) -> Result<Transfer<TContext>, TransferRequest<TContext>> {
        let cell = Arc::new(Mutex::new(Cell {
            outcome: None,
            waker: None,
        }));
        let request = map_context(request, |user| Awaited {
            user,
            cell: Arc::clone(&cell),
        });
        match self.inner.submit(request) {
            Ok(()) => Ok(Transfer { cell }),
            Err(request) => Err(map_context(request, |awaited| awaited.user)),
        }
    }

    /// Register `storage` so operands using it avoid `fi_mr_reg`. Same rules
    /// as [`crate::FabricService::register`]
    pub fn register<S>(&self, storage: S) -> Result<MemoryRegion<S>, DmaError>
    where
        S: AsRef<[u8]> + Send + Sync + 'static,
    {
        self.inner.register(storage)
    }

    /// This endpoint's fabric address, for your control channel. See [`crate::FabricService`].
    pub fn local_address(&self) -> &[u8] {
        self.inner.local_address()
    }

    /// The ack buffer descriptor clients use to send acknowledgements back to this server.
    /// Returns `None` if ack buffer registration failed.
    pub fn ack_buffer_info(&self) -> Option<crate::endpoint::AckBufferInfo> {
        self.inner.ack_buffer_info()
    }

    /// Count of submitted but unfinished transfers.
    pub fn outstanding(&self) -> usize {
        self.inner.outstanding()
    }

    /// Insert a client's peer address ahead of its first transfer. See
    /// [`crate::FabricService::add_peer`].
    pub fn add_peer(&self, client_id: u64, address: &[u8]) -> Result<(), DmaError> {
        self.inner.add_peer(client_id, address)
    }

    /// Drop a disconnected client's address-vector entry once its transfers drain.
    pub fn remove_peer(&self, client_id: u64) {
        self.inner.remove_peer(client_id);
    }
}
