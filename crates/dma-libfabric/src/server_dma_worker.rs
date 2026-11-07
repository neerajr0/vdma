use crate::sys::FI_EAGAIN;
use crate::sys::fi_context2;
use dma_libfabric_protocol::DmaError;
use dma_libfabric_protocol::checksum;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::os::raw::c_void;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Instant;

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::BatchCompleter;
use crate::Completion;
use crate::Configuration;
use crate::Direction;
use crate::Operands;
use crate::TransferDone;
use crate::TransferRequest;
use crate::endpoint::LibfabricEndpoint;
use crate::error::fabric_error;
use crate::local_regions::LocalOperand;
use crate::pool::Pool;
use crate::region_cache::Registration;
use crate::reply::Answer;
use crate::server::WorkerMessage;

/// Completions to reap in one pass, and the batch size that triggers a flush — bounding what one
/// batch, and so one downstream lock acquisition, accumulates.
const TARGET_COMPLETIONS: usize = 10;

/// A ToPeer operation whose local write has completed but is still awaiting its ack from the client.
/// Stored in `awaiting_ack` keyed by `transfer_id` until the matching ack arrives.
struct AwaitingAck<T> {
    /// The in-flight operation, already reaped from the local completion.
    inflight: Box<InFlight<T>>,
    /// The result from the local write completion (Ok or error).
    write_result: Result<(), DmaError>,
}

pub fn worker_main<T: Operands + Send + 'static>(
    configuration: Configuration,
    ready: Answer<Result<crate::server::EndpointReadyInfo, DmaError>>,
    receiver: &Receiver<WorkerMessage<T>>,
    complete_batch: Arc<BatchCompleter<T>>,
    pool: Arc<Pool>,
    outstanding: &AtomicUsize,
) {
    // The endpoint's fabric address doubles as the readiness signal — clients insert it via
    // dma.hello so the server can RMA against them on efa-direct.
    let mut endpoint = match LibfabricEndpoint::open(&configuration, configuration.bind.as_deref())
        .and_then(|endpoint| {
            let address = endpoint.local_address()?;
            let ack_buffer = endpoint.ack_buffer_info();
            Ok((endpoint, address, ack_buffer))
        }) {
        Ok((endpoint, address, ack_buffer)) => {
            ready.send(Ok(crate::server::EndpointReadyInfo { address, ack_buffer }));
            endpoint
        }
        Err(error) => {
            ready.send(Err(error));
            return;
        }
    };

    let cap = in_flight_cap(&endpoint, configuration.max_in_flight);
    let again = -(FI_EAGAIN as isize);
    let progress_deadline = configuration.progress_deadline;
    // Outstanding (queued or in-flight) ops per client, and clients whose peer to remove once that
    // count hits 0. Counting from intake rather than posting stops a removal slipping between a
    // queued transfer and its post, where the post would re-insert the peer just removed. Deferring
    // `fi_av_remove` to 0 also keeps it from flushing a live queue pair — the failure this prevents.
    let mut outstanding_by_client: HashMap<u64, usize> = HashMap::new();
    let mut pending_removal: HashSet<u64> = HashSet::new();
    let mut pending: VecDeque<Prepared<T>> = VecDeque::new();
    let mut in_flight: usize = 0;
    let mut reaped: Vec<(*mut c_void, Result<(), DmaError>)> = Vec::new();
    let mut disconnected = false;

    let mut completions: Vec<Completion<T>> = Vec::new();
    // Reaped ops wanting a checksum: their CRC + reply runs on the pool so hashing doesn't stall
    // posting and reaping. The rest complete inline.
    let mut crc_pending: Vec<ReapedOp<T>> = Vec::new();
    let mut drain_spins = 0;

    // For ToPeer ops: track in-flight operations awaiting their ack by transfer_id.
    // When the local write completes, we move the InFlight here until the ack arrives.
    let mut awaiting_ack: HashMap<u32, AwaitingAck<T>> = HashMap::new();
    // Acks that arrived before their local write completion (same CQ batch or earlier pass).
    // Checked and removed in the reaped drain loop to avoid parking an already-acked op.
    let mut early_acks: HashSet<u32> = HashSet::new();
    // Ack completions received this pass (transfer_ids echoed back by clients).
    let mut ack_completions: Vec<u32> = Vec::new();

    loop {
        // Intake: drain the channel without blocking.
        loop {
            match receiver.try_recv() {
                Ok(WorkerMessage::Transfer(request)) => accept(
                    request,
                    &mut outstanding_by_client,
                    outstanding,
                    &mut pending,
                    &mut completions,
                ),
                Ok(WorkerMessage::AddPeer {
                    client_id,
                    address,
                    reply,
                }) => {
                    reply.send(endpoint.insert_peer(client_id, &address).map(|_| ()));
                }
                Ok(WorkerMessage::RemovePeer(client_id)) => {
                    drain_client_acks(
                        client_id,
                        &mut awaiting_ack,
                        &mut endpoint,
                        &mut outstanding_by_client,
                        &mut pending_removal,
                        outstanding,
                        &mut completions,
                    );
                    remove_or_defer(
                        &mut endpoint,
                        &outstanding_by_client,
                        &mut pending_removal,
                        client_id,
                    );
                }
                // The submitter is blocked on this reply, so answer even when the pin fails.
                Ok(WorkerMessage::Register {
                    base,
                    length,
                    reply,
                }) => {
                    reply.send(endpoint.pin_region(base, length));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        // Post up to the cap, one pass over the queue.
        let mut posted = 0usize;
        let mut attempts = pending.len();
        while in_flight < cap && 0 < attempts {
            attempts -= 1;
            let Some(mut prepared) = pending.pop_front() else {
                break;
            };
            let error = match post(&mut endpoint, &prepared) {
                Ok(0) => {
                    in_flight += 1;
                    posted += 1;
                    continue;
                }
                Ok(code) if code == again => {
                    let stalled_since = *prepared.stalled_since.get_or_insert_with(Instant::now);
                    if stalled_since.elapsed() < progress_deadline {
                        pending.push_back(prepared);
                        continue;
                    }
                    DmaError::Transfer(format!(
                        "no progress posting for {progress_deadline:?}: peer unreachable or transmit queue stuck"
                    ))
                }
                Ok(code) => fabric_error(code as i32, "post"),
                Err(error) => error,
            };
            // Post failed outright: the op finishes here and is never reaped, so account it.
            let client_id = prepared.client_id;
            completions.push(reclaim(prepared.context).into_completion(Err(error)));
            finish_op(
                &mut endpoint,
                &mut outstanding_by_client,
                &mut pending_removal,
                outstanding,
                client_id,
            );
        }

        // Reap up to 10, then dispatch — bounding what one batch, and so one downstream lock
        // acquisition, accumulates. Use reap_all to get both local completions and ack completions
        // in one CQ pass.
        reaped.clear();
        ack_completions.clear();
        if let Err(error) = endpoint.reap_all(&mut reaped, &mut ack_completions, TARGET_COMPLETIONS) {
            // Names no op, so no client can be failed for it. Keep serving: the ops it did yield are
            // in `reaped`, and the rest stay in flight for a later pass.
            tracing::warn!("completion queue read failed: {error}");
        }

        // Process ack completions first: match them to ops awaiting ack by transfer_id.
        for transfer_id in ack_completions.drain(..) {
            if let Some(mut waiting) = awaiting_ack.remove(&transfer_id) {
                // Got the ack, mark it and complete the operation.
                waiting.inflight.ack_done = true;
                tracing::info!(transfer_id, "ACK received, completing ToPeer op");
                let inflight = waiting.inflight;
                let result = waiting.write_result;
                // Now we can finish the op and decrement the client's outstanding count.
                finish_op(
                    &mut endpoint,
                    &mut outstanding_by_client,
                    &mut pending_removal,
                    outstanding,
                    inflight.client_id,
                );
                if inflight.want_checksum {
                    crc_pending.push((inflight, result));
                } else {
                    completions.push(inflight.into_completion(result));
                }
            } else {
                // Ack arrived before the local write completion (same batch or earlier pass).
                // Stash it so the reaped-drain loop can match it immediately.
                tracing::debug!(transfer_id, "ack arrived before local completion, stashing");
                early_acks.insert(transfer_id);
            }
        }

        // Saturating because a reap that outran `in_flight` would otherwise wrap and leave the
        // worker unable to post again — stalling every client on this device, silently.
        in_flight = in_flight.saturating_sub(reaped.len());
        let reaped_any = !reaped.is_empty();
        // `in_flight` is the live pipeline depth — at c=1 it pins at 1. Emitted only when
        // something moved this pass.
        if 0 < posted || reaped_any {
            let _pass = tracing::debug_span!(
                parent: None,
                "worker_pass",
                in_flight,
                posted,
                reaped = reaped.len(),
                pending = pending.len(),
                awaiting_ack = awaiting_ack.len(),
            );
        }
        for (context, result) in reaped.drain(..) {
            let mut inflight = reclaim(context.cast::<InFlight<T>>());
            inflight.write_done = true;

            // For ToPeer ops with a transfer_id, wait for the ack before completing.
            // For FromPeer ops (transfer_id == 0), complete immediately.
            if inflight.transfer_id != 0 {
                // ToPeer: check if the ack already arrived (same batch or earlier pass).
                let transfer_id = inflight.transfer_id;
                if early_acks.remove(&transfer_id) {
                    // Ack beat the local completion — complete immediately.
                    inflight.ack_done = true;
                    tracing::info!(transfer_id, "ToPeer write done, early ack matched");
                    finish_op(
                        &mut endpoint,
                        &mut outstanding_by_client,
                        &mut pending_removal,
                        outstanding,
                        inflight.client_id,
                    );
                    if inflight.want_checksum {
                        crc_pending.push((inflight, result));
                    } else {
                        completions.push(inflight.into_completion(result));
                    }
                } else {
                    // Park in awaiting_ack until the client's ack arrives.
                    tracing::info!(transfer_id, "ToPeer write done, awaiting ack");
                    awaiting_ack.insert(transfer_id, AwaitingAck {
                        inflight,
                        write_result: result,
                    });
                    // Don't call finish_op yet — we'll do it when the ack arrives.
                }
            } else {
                // FromPeer or no-ack path: complete immediately.
                finish_op(
                    &mut endpoint,
                    &mut outstanding_by_client,
                    &mut pending_removal,
                    outstanding,
                    inflight.client_id,
                );
                // Checksummed ops carry their CRC into the completion, so defer the whole completion to
                // the pool rather than hash here. The rest are cheap enough to finish inline.
                if inflight.want_checksum {
                    crc_pending.push((inflight, result));
                } else {
                    completions.push(inflight.into_completion(result));
                }
            }
        }

        if should_flush_crc(
            crc_pending.len(),
            posted,
            reaped_any,
            pending.is_empty() && 0 == in_flight && awaiting_ack.is_empty(),
        ) {
            submit_crc_batch(&pool, &complete_batch, std::mem::take(&mut crc_pending));
        }

        if !completions.is_empty() {
            if completions.len() < TARGET_COMPLETIONS && drain_spins < 10 {
                // let's not run `complete_batch` again juuuust yet.
                std::hint::spin_loop();
                drain_spins += 1;
                continue;
            }
            drain_spins = 0;
            (*complete_batch)(completions.drain(..));
        }

        if disconnected && pending.is_empty() && 0 == in_flight && awaiting_ack.is_empty() {
            break;
        }
        if 0 == in_flight && pending.is_empty() && awaiting_ack.is_empty() {
            // Nothing outstanding: block on the channel to release the core.
            match receiver.recv() {
                Ok(WorkerMessage::Transfer(request)) => accept(
                    request,
                    &mut outstanding_by_client,
                    outstanding,
                    &mut pending,
                    &mut completions,
                ),
                Ok(WorkerMessage::AddPeer {
                    client_id,
                    address,
                    reply,
                }) => {
                    reply.send(endpoint.insert_peer(client_id, &address).map(|_| ()));
                }
                // Nothing is outstanding here, so this client has no ops to drain: remove now.
                Ok(WorkerMessage::RemovePeer(client_id)) => remove_or_defer(
                    &mut endpoint,
                    &outstanding_by_client,
                    &mut pending_removal,
                    client_id,
                ),
                Ok(WorkerMessage::Register {
                    base,
                    length,
                    reply,
                }) => {
                    reply.send(endpoint.pin_region(base, length));
                }
                Err(_) => break, // channel closed and nothing left → shutdown
            }
        } else if 0 == posted && !reaped_any {
            if 0 == in_flight && awaiting_ack.is_empty() {
                // Everything pending is stalled on -FI_EAGAIN, peers connecting or gone. There is
                // nothing to reap, so busy-polling probably won't help much. Make sure the core is
                // available to other work since it probably isn't useful here for at least a few
                // hundred microseconds.
                std::thread::yield_now();
            } else {
                // Work in flight or awaiting acks but nothing moved this pass: stay hot for the completion.
                std::hint::spin_loop();
            }
        }
    }

    // Shutdown: fail never-posted requests, ops awaiting ack, and finish deferred checksummed
    // completions inline, since the pool may be tearing down alongside us.
    let mut leftover: Vec<Completion<T>> = pending
        .drain(..)
        .map(|prepared| {
            let error = DmaError::Fabric("fabric worker is gone".into());
            reclaim(prepared.context).into_completion(Err(error))
        })
        .chain(
            // Ops awaiting ack that never got one — complete them with their write result.
            // The ack never came, but the write itself may have succeeded.
            awaiting_ack
                .drain()
                .map(|(_, waiting)| waiting.inflight.into_completion(waiting.write_result)),
        )
        .chain(
            crc_pending
                .into_iter()
                .map(|(op, result)| op.into_completion(result)),
        )
        .collect();
    if !leftover.is_empty() {
        (*complete_batch)(leftover.drain(..));
    }
}

/// Whether to hand the accumulated checksummed completions to the pool this pass: when the batch
/// fills, when nothing moved, or when the worker is about to park.
///
/// `about_to_park` is the one that must never be dropped. The worker blocks on the channel with
/// nothing left to post or reap, so a batch held back here waits for an unrelated message to wake
/// the worker — stranding every client in it until then.
fn should_flush_crc(batched: usize, posted: usize, reaped_any: bool, about_to_park: bool) -> bool {
    0 < batched && (batched >= TARGET_COMPLETIONS || (0 == posted && !reaped_any) || about_to_park)
}

/// Finish checksummed completions on the pool: hash each payload, then run the batch's
/// `complete_batch`, all off the fabric worker.
fn submit_crc_batch<T: Operands + Send + 'static>(
    pool: &Arc<Pool>,
    complete_batch: &Arc<BatchCompleter<T>>,
    batch: Vec<ReapedOp<T>>,
) {
    let complete = Arc::clone(complete_batch);
    pool.submit(Box::new(move || {
        let mut done: Vec<Completion<T>> = batch
            .into_iter()
            .map(|(op, result)| op.into_completion(result))
            .collect();
        (*complete)(done.drain(..));
    }));
}

/// Queue a submitted transfer, or complete it when its operand doesn't resolve.
fn accept<T: Operands>(
    request: TransferRequest<T>,
    outstanding_by_client: &mut HashMap<u64, usize>,
    outstanding: &AtomicUsize,
    pending: &mut VecDeque<Prepared<T>>,
    completions: &mut Vec<Completion<T>>,
) {
    match prepare(request) {
        Ok(prepared) => {
            *outstanding_by_client.entry(prepared.client_id).or_insert(0) += 1;
            pending.push_back(prepared);
        }
        Err(completion) => {
            release_outstanding(outstanding);
            completions.push(completion);
        }
    }
}

/// Remove a disconnected client's peer, or defer until its last op finishes. Removing with ops
/// outstanding would flush the queue pair, and a queued transfer would re-insert the peer.
fn remove_or_defer(
    endpoint: &mut LibfabricEndpoint,
    outstanding_by_client: &HashMap<u64, usize>,
    pending_removal: &mut HashSet<u64>,
    client_id: u64,
) {
    if 0 == outstanding_by_client.get(&client_id).copied().unwrap_or(0) {
        endpoint.release_peer(client_id);
    } else {
        pending_removal.insert(client_id);
    }
}

/// Drain `awaiting_ack` entries belonging to a disconnected client. Completes each op with its
/// write result (the write succeeded, but the ack will never arrive) and decrements the client's
/// outstanding count so `remove_or_defer` can release the peer.
fn drain_client_acks<T: Operands>(
    client_id: u64,
    awaiting_ack: &mut HashMap<u32, AwaitingAck<T>>,
    endpoint: &mut LibfabricEndpoint,
    outstanding_by_client: &mut HashMap<u64, usize>,
    pending_removal: &mut HashSet<u64>,
    outstanding: &AtomicUsize,
    completions: &mut Vec<Completion<T>>,
) {
    let drain_ids: Vec<u32> = awaiting_ack
        .iter()
        .filter(|(_, w)| w.inflight.client_id == client_id)
        .map(|(&id, _)| id)
        .collect();
    for id in drain_ids {
        if let Some(waiting) = awaiting_ack.remove(&id) {
            tracing::info!(transfer_id = id, client_id, "draining ack for disconnected client");
            finish_op(
                endpoint,
                outstanding_by_client,
                pending_removal,
                outstanding,
                client_id,
            );
            completions.push(waiting.inflight.into_completion(waiting.write_result));
        }
    }
}

/// Account one finished op, reaped or failed to post, against its client, performing a deferred peer
/// removal when its last op drains.
fn finish_op(
    endpoint: &mut LibfabricEndpoint,
    outstanding_by_client: &mut HashMap<u64, usize>,
    pending_removal: &mut HashSet<u64>,
    outstanding: &AtomicUsize,
    client_id: u64,
) {
    release_outstanding(outstanding);
    let remaining = match outstanding_by_client.get_mut(&client_id) {
        Some(count) => {
            *count -= 1;
            *count
        }
        None => 0,
    };
    if 0 == remaining {
        outstanding_by_client.remove(&client_id);
        if pending_removal.remove(&client_id) {
            endpoint.release_peer(client_id);
        }
    }
}

/// Drop one op from the device-wide tally `submit` raised.
fn release_outstanding(outstanding: &AtomicUsize) {
    // gotta saturate so it never sees a spurious wrap state
    outstanding.update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.saturating_sub(1)
    });
}

/// A reaped op awaiting its checksummed completion on the pool.
type ReapedOp<T> = (Box<InFlight<T>>, Result<(), DmaError>);

/// Reclaim ownership of an `InFlight` from its `op_context` pointer. Called once per op: on its
/// completion, or inline on a post failure or shutdown.
fn reclaim<T>(context: *mut InFlight<T>) -> Box<InFlight<T>> {
    // SAFETY: the pointer came from `Box::into_raw` in `prepare` and is reclaimed once.
    unsafe { Box::from_raw(context) }
}

/// Post one prepared transfer, returning the raw libfabric code (`0` posted, `-FI_EAGAIN` transmit
/// queue full, else error), or `Err` for a setup failure: peer insert or region registration.
fn post<T: Operands>(
    endpoint: &mut LibfabricEndpoint,
    prepared: &Prepared<T>,
) -> Result<isize, DmaError> {
    let peer = endpoint.insert_peer(prepared.client_id, &prepared.peer_address)?;
    let context = prepared.context.cast::<c_void>();
    let length = prepared.length;
    // Asked only on a registration cache miss, so a caller's per-extent setup runs once per
    // registration rather than once per transfer.
    // SAFETY: `context` is this operation's live `InFlight`, and nothing else touches it until posted.
    let cacheable_span = || unsafe { (*prepared.context).caller_context.cacheable_span() };
    let LocalOperand { descriptor, lease } =
        endpoint.local_operand(prepared.pointer, length, cacheable_span)?;
    let connection = endpoint.connection(&peer, prepared.remote_key, prepared.remote_address);
    // On-wire time, as an explicit child of the caller's `dma.get`/`dma.set` span so the transfer
    // tree covers setup -> wire -> completion without entering the parent on this thread. Stored in
    // the operation, so it stays open until completion.
    let wire = tracing::info_span!(
        parent: prepared.parent_id.clone(),
        "wire",
        direction = ?prepared.direction,
        length
    );
    let code = {
        // so the post spans are children of the wire span
        let _posting = wire.enter();
        match prepared.direction {
            Direction::ToPeer => {
                // SAFETY: the operand lives in the caller context, which the `InFlight` holds until
                //         the completion runs.
                let bytes = unsafe { std::slice::from_raw_parts(prepared.pointer, length) };
                // Use post_out_with_immediate to send FI_REMOTE_CQ_DATA with the write.
                // The immediate data is a unique transfer_id so the client can echo it back
                // in its ack for correlation. With the `efa` (rxr) provider, this generates a CQ
                // entry at the client without requiring posted receive buffers.
                let transfer_id = endpoint.next_transfer_id();
                // Store the transfer_id in InFlight so we can match incoming acks to this write.
                // SAFETY: `prepared.context` is this operation's live `InFlight`, and nothing else
                //         touches it until the completion.
                unsafe {
                    (*prepared.context).transfer_id = transfer_id;
                }
                connection.post_out_with_immediate(bytes, descriptor, context, transfer_id)
            }
            Direction::FromPeer { .. } => {
                // SAFETY: as above; no other thread touches the buffer until completion.
                let bytes = unsafe { std::slice::from_raw_parts_mut(prepared.pointer, length) };
                connection.post_in(bytes, descriptor, context)
            }
        }
    };
    if 0 == code {
        // Hand both spans to the in-flight operation so they live until it is reaped.
        let await_completion = tracing::info_span!(parent: &wire, "await_completion");
        // SAFETY: `context` is this operation's live `InFlight`, valid until the completion runs, and no
        //         other thread touches it until then.
        unsafe {
            (*prepared.context).wire_span = wire;
            (*prepared.context).await_span = await_completion;
            // Held until the completion drops the operation: while this lease lives the region
            // cannot be deregistered, so a concurrent reclaim cannot pull it out from under the
            // descriptor this post just handed to libfabric.
            (*prepared.context).local_lease = lease;
        }
    }
    Ok(code)
}

/// The in-flight cap, clamped to the provider's transmit-queue depth so we self-limit below
/// `-FI_EAGAIN`.
fn in_flight_cap(endpoint: &LibfabricEndpoint, configured: Option<usize>) -> usize {
    // A few tens saturate the network card at large payloads while bounding pinned memory, since
    // each in-flight op pins its buffer.
    let requested = configured.unwrap_or(64).max(1);
    // `tx_attr.size` is 0 when the provider reports no fixed depth; clamping to that would cap at 1
    // and serialize everything.
    match endpoint.max_tx() {
        0 => requested,
        hardware => requested.min(hardware),
    }
}

/// Per-op state. Its pointer is the `op_context` handed to libfabric and recovered on completion.
#[repr(C)]
struct InFlight<T> {
    /// `#[repr(C)]` with this field first gives `&inflight == &inflight._context2`, so passing the
    /// `InFlight` pointer as `op_context` satisfies `FI_CONTEXT2` and the completion hands the whole
    /// struct back — no separate in-flight table needed. The efa-direct provider owns these 64 bits
    /// for the op's duration; never read them. Providers without `FI_CONTEXT2` (tcp, rxr efa) ignore
    /// the contents.
    _context2: fi_context2,
    /// For users of this crate: completion callbacks and whatever else the call carries.
    caller_context: T,
    /// The submitting client, so reaping decrements its in-flight count and fires a deferred peer
    /// removal once its last op drains.
    client_id: u64,
    length: usize,
    /// Whether the caller wants a checksum, taken over the operand at completion, on the pool.
    want_checksum: bool,
    /// The local operand: the source for `ToPeer`, the landing buffer for `FromPeer`.
    buffer_pointer: *mut u8,
    /// The operand's lease on its registration, held from post until this op is reaped and its
    /// `InFlight` dropped. An uncached extent is deregistered right there, being its only holder; a
    /// cached one only if a reclaim already retired it from the registry. `None` until posted, and
    /// on providers needing no local registration.
    local_lease: Option<Arc<Registration>>,
    /// Post to reap: the on-wire duration. `Span::none()` until posted, and when tracing is off.
    wire_span: tracing::Span,
    /// Child of `wire_span` covering only the wait, from `fi_*` returning to the completion reaped.
    await_span: tracing::Span,
    /// The unique transfer ID sent as immediate data in `ToPeer` writes. The client echoes this
    /// back in its ack, allowing correlation. 0 for `FromPeer` or when no ack is expected.
    transfer_id: u32,
    /// True once the local write completion has been reaped (data transmitted to client).
    /// For `FromPeer` ops this is the only completion needed.
    write_done: bool,
    /// True once the client's ack with matching `transfer_id` has been received.
    /// Only meaningful for `ToPeer` ops; `FromPeer` ops don't wait for acks.
    ack_done: bool,
}

// SAFETY: moved to a pool worker to finish a checksummed completion. Its raw pointers reference the
// operand, kept alive by `caller_context` until the completion runs, and the provider-owned
// `_context2` scratch, untouched after the op is reaped.
unsafe impl<T: Send> Send for InFlight<T> {}

impl<T> InFlight<T> {
    /// Turn a raw libfabric result into a [`Completion`], hashing the operand if asked. Checksummed
    /// ops run this on a pool worker, keeping the hash off the fabric worker.
    ///
    /// Takes the box rather than its contents so the hash runs before the caller context moves. The
    /// operand may live inside that context, and the box keeps the address stable since `prepare`.
    #[expect(
        clippy::boxed_local,
        reason = "the box pins the operand's address across the hash"
    )]
    fn into_completion(self: Box<Self>, result: Result<(), DmaError>) -> Completion<T> {
        let outcome = result.map(|()| {
            let checksum_value = self.want_checksum.then(|| {
                let _span =
                    tracing::info_span!(parent: &self.wire_span, "checksum", length = self.length)
                        .entered();
                // SAFETY: the operand is the caller context's, still held by this `InFlight`.
                checksum(unsafe { std::slice::from_raw_parts(self.buffer_pointer, self.length) })
            });
            TransferDone {
                bytes: self.length,
                checksum: checksum_value,
            }
        });
        Completion {
            caller_context: self.caller_context,
            outcome,
        }
    }
}

/// A request whose `InFlight` box is already built, so an `-FI_EAGAIN` deferral holds it cheaply,
/// plus the parameters needed to post.
struct Prepared<T> {
    context: *mut InFlight<T>,
    client_id: u64,
    peer_address: Vec<u8>,
    remote_key: u64,
    remote_address: u64,
    /// The resolved local operand pointer must stay valid for the post.
    pointer: *mut u8,
    length: usize,
    direction: Direction,
    /// The caller's transfer span, parent of the on-wire span.
    parent_id: Option<tracing::span::Id>,
    /// When the provider first answered this op `-FI_EAGAIN`; the progress deadline counts from
    /// here. After posting, the op is gone, so this never needs clearing.
    stalled_since: Option<Instant>,
}

/// Build the per-op `InFlight` box and the post parameters, resolving the local operand out of the
/// caller's context.
/// Both run on the worker thread, keeping allocation off the submitting thread.
fn prepare<T: Operands>(request: TransferRequest<T>) -> Result<Prepared<T>, Completion<T>> {
    let mut inflight = Box::new(InFlight {
        // Provider-owned scratch; it initializes this when the op is posted.
        _context2: unsafe { std::mem::zeroed() },
        caller_context: request.caller_context,
        client_id: request.client_id,
        // Both set just below, once the operand resolves.
        length: 0,
        buffer_pointer: std::ptr::null_mut(),
        want_checksum: request.want_checksum,
        // Set at post time, once the operand is registered.
        local_lease: None,
        wire_span: tracing::Span::none(),
        await_span: tracing::Span::none(),
        // Set at post time for ToPeer writes; 0 for FromPeer.
        transfer_id: 0,
        // Completion tracking: both start false, set true as completions arrive.
        write_done: false,
        ack_done: false,
    });
    let operand = match request.direction {
        Direction::ToPeer => match inflight.caller_context.source() {
            Some(bytes) => Ok((bytes.as_ptr().cast_mut(), bytes.len())),
            None => Err(DmaError::Fabric(
                "the caller context supplied no source bytes for a ToPeer transfer".into(),
            )),
        },
        Direction::FromPeer { length } => match inflight.caller_context.allocate(length) {
            // Overrunning a short landing buffer would corrupt whatever follows it, so refuse.
            Some(landing) if landing.len() < length => Err(DmaError::Fabric(format!(
                "the caller context allocated {} bytes for a {length} byte FromPeer transfer",
                landing.len()
            ))),
            Some(landing) => Ok((landing.as_mut_ptr(), length)),
            None => Err(DmaError::Fabric(
                "the caller context allocated no landing buffer for a FromPeer transfer".into(),
            )),
        },
    };
    let (pointer, length) = match operand {
        Ok(operand) => operand,
        Err(error) => {
            return Err(Completion {
                caller_context: inflight.caller_context,
                outcome: Err(error),
            });
        }
    };
    inflight.buffer_pointer = pointer;
    inflight.length = length;
    Ok(Prepared {
        context: Box::into_raw(inflight),
        client_id: request.client_id,
        peer_address: request.peer_address,
        remote_key: request.remote_key,
        remote_address: request.remote_address,
        pointer,
        length,
        direction: request.direction,
        parent_id: request.parent_id,
        stalled_since: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{TARGET_COMPLETIONS, should_flush_crc};

    /// The worker is about to block on the channel, so a held-back batch would wait for an unrelated
    /// message to wake it — the clients in it hang until then. This is what a reaped checksummed
    /// transfer hit: batch of 1, nothing posted, but `reaped_any` true, so neither of the other two
    /// conditions fired.
    #[test]
    fn flushes_a_partial_batch_before_parking() {
        assert!(should_flush_crc(1, 0, true, true));
    }

    #[test]
    fn flushes_a_full_batch_even_with_work_left() {
        assert!(should_flush_crc(TARGET_COMPLETIONS, 4, true, false));
    }

    /// Nothing moved this pass, so a partial batch shouldn't wait on future work.
    #[test]
    fn flushes_a_partial_batch_when_nothing_moved() {
        assert!(should_flush_crc(1, 0, false, false));
    }

    /// Work is still in flight and the batch is partial: let it fill.
    #[test]
    fn holds_a_partial_batch_while_work_is_moving() {
        assert!(!should_flush_crc(1, 1, true, false));
    }

    #[test]
    fn never_flushes_an_empty_batch() {
        assert!(!should_flush_crc(0, 0, false, true));
    }
}
