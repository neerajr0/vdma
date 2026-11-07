//! A local libfabric endpoint: fabric, domain, address vector, completion queue, and an enabled
//! `FI_EP_RDM` endpoint. All owned, and closed on drop in reverse construction order.

use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;

use std::sync::atomic::{AtomicU32, Ordering};

use crate::sys::{
    FI_EAGAIN, FI_EAVAIL, FI_MR_ALLOCATED, FI_MR_ENDPOINT, FI_MR_HMEM, FI_MR_LOCAL, FI_MR_PROV_KEY,
    FI_MR_VIRT_ADDR, FI_MSG, FI_READ, FI_RECV, FI_REMOTE_CQ_DATA, FI_REMOTE_READ, FI_REMOTE_WRITE,
    FI_RMA, FI_SOURCE, FI_TRANSMIT, FI_WRITE, fi_allocinfo, fi_av_attr, fi_av_open,
    fi_av_type_FI_AV_MAP, fi_cq_attr, fi_cq_data_entry, fi_cq_err_entry,
    fi_cq_format_FI_CQ_FORMAT_DATA, fi_cq_open, fi_cq_read, fi_cq_readerr, fi_domain, fi_dupinfo,
    fi_enable, fi_endpoint, fi_ep_bind, fi_ep_type_FI_EP_RDM, fi_fabric, fi_freeinfo, fi_getinfo,
    fi_getname, fi_info, fi_mr_key, fi_mr_reg, fi_version, fid_av, fid_cq, fid_domain, fid_ep,
    fid_fabric, fid_mr,
};
use dma_libfabric_protocol::DmaError;

/// Magic value sent as immediate data in ack completions. Clients send this to signal they have
/// received all data; servers poll for it before replying OK.
pub const ACK_MAGIC: u64 = 0xACACACAC;

/// Size of the ack buffer. Small and fixed — clients write a tiny payload with the real signal
/// carried in the immediate data field.
const ACK_BUFFER_SIZE: usize = 8;

/// Descriptor for a remotely-writable ack buffer. Returned by [`LibfabricEndpoint::ack_buffer_info`]
/// and advertised to clients so they can send acknowledgements back to the server.
#[derive(Debug, Clone, Copy)]
pub struct AckBufferInfo {
    /// The remote key for the ack buffer registration.
    pub rkey: u64,
    /// The remote address (virtual address on FI_MR_VIRT_ADDR providers, 0 otherwise).
    pub remote_addr: u64,
    /// The buffer length.
    pub len: usize,
}

use crate::configuration::{Configuration, Provider};
use crate::connection::LibfabricConnection;
use crate::error::{check, fabric_error};
use crate::local_regions::{LocalOperand, LocalRegions};
use crate::operands::CacheableSpan;
use crate::peer_addresses::{AddressFormat, PeerAddresses, RegisteredAddress};

/// Guard a completion's `op_context` before the caller reclaims it as an owned allocation. A
/// provider reporting a completion for an op we never posted would otherwise be boxed from null.
fn non_null_context(context: *mut c_void) -> Result<*mut c_void, DmaError> {
    if context.is_null() {
        return Err(DmaError::Fabric(
            "completion carried a null op_context".into(),
        ));
    }
    Ok(context)
}

/// An open, enabled local endpoint.
#[derive(Debug)]
pub struct LibfabricEndpoint {
    endpoint: *mut fid_ep,
    completion_queue: *mut fid_cq,
    address_vector: *mut fid_av,
    domain: *mut fid_domain,
    fabric: *mut fid_fabric,
    info: *mut fi_info,
    /// `FI_MR_LOCAL`, as efa does: local RMA buffers must be registered and a descriptor passed.
    requires_local_mr: bool,
    /// `FI_MR_VIRT_ADDR`, as efa does: remote RMA addresses are virtual addresses, not offsets.
    uses_virtual_addressing: bool,
    /// `tx_attr.size`: operations the transmit context accepts before `-FI_EAGAIN`.
    max_tx: usize,
    /// Registrations covering the memory used as RMA operands, so the hot path reuses a descriptor
    /// instead of calling `fi_mr_reg` per op.
    local_regions: LocalRegions,
    /// Address-vector entries, shared between clients advertising the same address.
    peer_addresses: PeerAddresses,
    /// A small buffer registered for remote write access, so clients can send acknowledgements.
    /// The buffer itself is boxed to keep its address stable.
    ack_buffer: Option<Box<[u8; ACK_BUFFER_SIZE]>>,
    /// Memory region handle for the ack buffer. Closed on drop before the domain.
    ack_buffer_mr: *mut fid_mr,
    /// Cached ack buffer info (rkey, remote_addr) for advertisement to clients.
    ack_buffer_info: Option<AckBufferInfo>,
    /// Monotonic counter for generating unique transfer IDs. Used as immediate data in
    /// FI_REMOTE_CQ_DATA writes so clients can echo it back in acks for correlation.
    /// Wraps at u32::MAX, which is fine — collisions require 4B concurrent in-flight transfers.
    transfer_seq: AtomicU32,
}

/// Build the configured provider's hints and run `fi_getinfo`. The caller selects an entry from the
/// returned list and frees it with `fi_freeinfo`. Shared with domain discovery so the hints are
/// defined once.
pub(crate) fn query_info(
    configuration: &Configuration,
    source_node: Option<&str>,
) -> Result<*mut fi_info, DmaError> {
    let primary = configuration
        .providers
        .first()
        .copied()
        .unwrap_or(Provider::Tcp);
    let provider = CString::new(primary.as_str())
        .map_err(|_| DmaError::Fabric("invalid provider name".into()))?;
    // Pin a fabric when the provider name alone is ambiguous: efa exposes both the rxr `efa` fabric
    // and the device-RDMA `efa-direct` one. Kept alive until after fi_getinfo.
    let fabric_name = match primary.fabric_name() {
        Some(name) => {
            Some(CString::new(name).map_err(|_| DmaError::Fabric("invalid fabric name".into()))?)
        }
        None => None,
    };
    let node = match source_node {
        Some(node) => {
            Some(CString::new(node).map_err(|_| DmaError::Fabric("invalid source node".into()))?)
        }
        None => None,
    };

    let mut info: *mut fi_info = ptr::null_mut();
    unsafe {
        let hints = fi_allocinfo();
        if hints.is_null() {
            return Err(DmaError::Fabric("fi_allocinfo failed".into()));
        }
        let caps =
            u64::from(FI_MSG | FI_RMA | FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE);
        // Advertise the registration modes we support; libfabric returns the subset the provider
        // requires — none for tcp, `FI_MR_VIRT_ADDR` and friends for efa. Leaving this 0 makes efa
        // hand back a variant whose RMA still needs virtual addresses but reports mr_mode=0, which
        // fails with REMOTE_BAD_ADDRESS.
        let mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
        (*hints).caps = caps;
        (*(*hints).ep_attr).type_ = fi_ep_type_FI_EP_RDM;
        (*(*hints).domain_attr).mr_mode = mr_mode as i32;
        // Leave addr_format unspecified so each provider picks its native format — FI_SOCKADDR_IN
        // for tcp, its own fabric address for efa. Addresses are exchanged opaquely.
        (*(*hints).fabric_attr).prov_name = provider.as_ptr().cast_mut();
        // Pin the fabric when the provider exposes more than one.
        if let Some(name) = &fabric_name {
            (*(*hints).fabric_attr).name = name.as_ptr().cast_mut();
        }
        // `InFlight` satisfies FI_CONTEXT2 by making a `fi_context2` its first field.
        (*hints).mode |= primary.required_mode();
        // Leave progress unspecified so EFA uses its native FI_PROGRESS_AUTO.

        let (node_ptr, flags) = match &node {
            Some(node) => (node.as_ptr(), FI_SOURCE),
            None => (ptr::null(), 0),
        };
        let code = fi_getinfo(fi_version(), node_ptr, ptr::null(), flags, hints, &mut info);
        // Detach these so fi_freeinfo doesn't free the Rust-owned CStrings.
        (*(*hints).fabric_attr).prov_name = ptr::null_mut();
        (*(*hints).fabric_attr).name = ptr::null_mut();
        fi_freeinfo(hints);
        check(code, "fi_getinfo")?;
    }
    if info.is_null() {
        return Err(DmaError::Fabric("no provider matched".into()));
    }
    Ok(info)
}

/// The first entry in `list` whose fabric domain is named `want`, or null. Pins an endpoint to one
/// network card when an instance has several, each EFA being a distinct domain.
fn select_domain(list: *mut fi_info, want: &str) -> *mut fi_info {
    let mut node = list;
    // SAFETY: a valid fi_info list from `fi_getinfo`, only read and walked via `next`.
    unsafe {
        while !node.is_null() {
            let name = (*(*node).domain_attr).name;
            if !name.is_null() && CStr::from_ptr(name).to_str() == Ok(want) {
                return node;
            }
            node = (*node).next;
        }
    }
    ptr::null_mut()
}

impl LibfabricEndpoint {
    /// Open an endpoint for the configured provider, pinned to the first domain named in
    /// `configuration.interfaces`, or to the first the provider returns when that is empty.
    /// `source_node`, such as `"127.0.0.1"`, binds the local source address when given.
    pub fn open(
        configuration: &Configuration,
        source_node: Option<&str>,
    ) -> Result<Self, DmaError> {
        // All-null, so an early error drops a partially-built endpoint and closes only what opened.
        let mut endpoint = LibfabricEndpoint {
            endpoint: ptr::null_mut(),
            completion_queue: ptr::null_mut(),
            address_vector: ptr::null_mut(),
            domain: ptr::null_mut(),
            fabric: ptr::null_mut(),
            info: ptr::null_mut(),
            requires_local_mr: false,
            uses_virtual_addressing: false,
            max_tx: 0,
            local_regions: LocalRegions::new(ptr::null_mut()),
            peer_addresses: PeerAddresses::new(ptr::null_mut(), AddressFormat::Opaque),
            ack_buffer: None,
            ack_buffer_mr: ptr::null_mut(),
            ack_buffer_info: None,
            transfer_seq: AtomicU32::new(1), // Start at 1 so 0 can mean "no transfer"
        };

        let list = query_info(configuration, source_node)?;
        unsafe {
            // Copy the requested domain out standalone and free the list, so everything downstream
            // operates on the chosen device with no further selection.
            let wanted = configuration.interfaces.first().map(String::as_str);
            let chosen = match wanted {
                Some(name) => select_domain(list, name),
                None => list,
            };
            if chosen.is_null() {
                fi_freeinfo(list);
                return Err(DmaError::Fabric(format!(
                    "no fabric domain named {:?}",
                    wanted.unwrap_or_default()
                )));
            }
            endpoint.info = fi_dupinfo(chosen);
            fi_freeinfo(list);
            if endpoint.info.is_null() {
                return Err(DmaError::Fabric("fi_dupinfo failed".into()));
            }

            // Adapt to the selected provider's memory-registration requirements.
            let mr_mode = (*(*endpoint.info).domain_attr).mr_mode as u32;
            endpoint.requires_local_mr = mr_mode & FI_MR_LOCAL != 0;
            endpoint.uses_virtual_addressing = mr_mode & FI_MR_VIRT_ADDR != 0;
            endpoint.max_tx = (*(*endpoint.info).tx_attr).size;

            check(
                fi_fabric(
                    (*endpoint.info).fabric_attr,
                    &mut endpoint.fabric,
                    ptr::null_mut(),
                ),
                "fi_fabric",
            )?;
            check(
                fi_domain(
                    endpoint.fabric,
                    endpoint.info,
                    &mut endpoint.domain,
                    ptr::null_mut(),
                ),
                "fi_domain",
            )?;
            endpoint.local_regions = LocalRegions::new(endpoint.domain);

            let mut av_attr: fi_av_attr = std::mem::zeroed();
            av_attr.type_ = fi_av_type_FI_AV_MAP;
            check(
                fi_av_open(
                    endpoint.domain,
                    &mut av_attr,
                    &mut endpoint.address_vector,
                    ptr::null_mut(),
                ),
                "fi_av_open",
            )?;
            endpoint.peer_addresses = PeerAddresses::new(
                endpoint.address_vector,
                AddressFormat::from_fi((*endpoint.info).addr_format),
            );

            let mut cq_attr: fi_cq_attr = std::mem::zeroed();
            // Use FI_CQ_FORMAT_DATA to receive immediate data from FI_REMOTE_CQ_DATA writes.
            // This format includes the `data` field that carries the immediate value the remote
            // sender passed to fi_writemsg with FI_REMOTE_CQ_DATA.
            cq_attr.format = fi_cq_format_FI_CQ_FORMAT_DATA;
            check(
                fi_cq_open(
                    endpoint.domain,
                    &mut cq_attr,
                    &mut endpoint.completion_queue,
                    ptr::null_mut(),
                ),
                "fi_cq_open",
            )?;

            check(
                fi_endpoint(
                    endpoint.domain,
                    endpoint.info,
                    &mut endpoint.endpoint,
                    ptr::null_mut(),
                ),
                "fi_endpoint",
            )?;
            check(
                fi_ep_bind(endpoint.endpoint, &mut (*endpoint.address_vector).fid, 0),
                "fi_ep_bind(av)",
            )?;
            check(
                fi_ep_bind(
                    endpoint.endpoint,
                    &mut (*endpoint.completion_queue).fid,
                    u64::from(FI_TRANSMIT | FI_RECV),
                ),
                "fi_ep_bind(cq)",
            )?;
            check(fi_enable(endpoint.endpoint), "fi_enable")?;

            // Register a small ack buffer for remote write access. Clients send an
            // fi_writemsg with FI_REMOTE_CQ_DATA to this buffer to acknowledge they
            // received data; the server polls poll_remote_completions() for ACK_MAGIC.
            let ack_buf = Box::new([0u8; ACK_BUFFER_SIZE]);
            let ack_ptr = ack_buf.as_ptr();
            let mut ack_mr: *mut fid_mr = ptr::null_mut();
            check(
                fi_mr_reg(
                    endpoint.domain,
                    ack_ptr.cast::<c_void>(),
                    ACK_BUFFER_SIZE,
                    u64::from(FI_REMOTE_WRITE | FI_WRITE),
                    0,
                    0, // requested_key — provider assigns on FI_MR_PROV_KEY
                    0,
                    &mut ack_mr,
                    ptr::null_mut(),
                ),
                "fi_mr_reg(ack_buffer)",
            )?;
            let rkey = fi_mr_key(ack_mr);
            let remote_addr = if endpoint.uses_virtual_addressing {
                ack_ptr as u64
            } else {
                0 // offset-based addressing
            };
            endpoint.ack_buffer = Some(ack_buf);
            endpoint.ack_buffer_mr = ack_mr;
            endpoint.ack_buffer_info = Some(AckBufferInfo {
                rkey,
                remote_addr,
                len: ACK_BUFFER_SIZE,
            });
        }

        Ok(endpoint)
    }

    /// Outstanding transmit operations before the provider returns `-FI_EAGAIN`.
    pub fn max_tx(&self) -> usize {
        self.max_tx
    }

    /// The ack buffer descriptor for this endpoint, or `None` if registration failed.
    /// Clients use this to send acknowledgements back to the server via fi_writemsg
    /// with FI_REMOTE_CQ_DATA.
    pub fn ack_buffer_info(&self) -> Option<AckBufferInfo> {
        self.ack_buffer_info
    }

    /// Generate a unique transfer ID for use as immediate data in FI_REMOTE_CQ_DATA writes.
    /// Clients echo this back in their ack for correlation. Wraps at u32::MAX.
    pub fn next_transfer_id(&self) -> u32 {
        self.transfer_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Reap ready completions, appending `(op_context, result)` to `out` up to `max` or until the
    /// queue is empty. Each posted op completes once here: success entries carry their `op_context`,
    /// and an error completion's is recovered via `fi_cq_readerr`. It is whatever the poster passed
    /// to `fi_writemsg`/`fi_read`.
    ///
    /// Every appended `op_context` is non-null and came from a posted op — the caller reclaims it as
    /// an owned allocation. A queue-level failure that names no op is returned instead, never
    /// reported as a completion.
    pub fn reap(
        &self,
        out: &mut Vec<(*mut c_void, Result<(), DmaError>)>,
        max: usize,
    ) -> Result<(), DmaError> {
        self.reap_all(out, &mut Vec::new(), max)
    }

    /// Reap ready completions into two output vectors:
    /// - `local_out`: local operation completions (our posted writes/reads completing)
    /// - `ack_out`: remote ack completions (client's FI_REMOTE_CQ_DATA writes with transfer_id)
    ///
    /// Both types come from the same CQ in a single `fi_cq_read` pass, distinguished by:
    /// - Local completions have non-null `op_context`
    /// - Remote acks have `FI_REMOTE_CQ_DATA` flag and null `op_context`
    ///
    /// The `data` field of ack completions contains the `transfer_id` the client echoed back.
    pub fn reap_all(
        &self,
        local_out: &mut Vec<(*mut c_void, Result<(), DmaError>)>,
        ack_out: &mut Vec<u32>,
        max: usize,
    ) -> Result<(), DmaError> {
        const BATCH: usize = 16;
        let again = -(FI_EAGAIN as isize);
        // Only `-FI_EAVAIL` promises an entry in the error queue. Any other negative is a failure of
        // the queue itself, with nothing for `fi_cq_readerr` to return.
        let available = -(FI_EAVAIL as isize);
        let mut total_reaped = 0usize;
        while total_reaped < max {
            // Use fi_cq_data_entry to match FI_CQ_FORMAT_DATA set at CQ creation.
            let mut entries: [fi_cq_data_entry; BATCH] = unsafe { std::mem::zeroed() };
            let want = BATCH.min(max - total_reaped);
            let read =
                unsafe { fi_cq_read(self.completion_queue, entries.as_mut_ptr().cast(), want) };
            if 0 < read {
                for entry in &entries[..read as usize] {
                    total_reaped += 1;
                    // Remote ack completions: FI_REMOTE_CQ_DATA flag set, null op_context.
                    // The `data` field contains the transfer_id the client echoed back.
                    if entry.flags & u64::from(FI_REMOTE_CQ_DATA) != 0 {
                        ack_out.push(entry.data as u32);
                        continue;
                    }
                    // Local operation completions: non-null op_context.
                    if !entry.op_context.is_null() {
                        local_out.push((non_null_context(entry.op_context)?, Ok(())));
                    }
                }
            } else if read == again {
                break; // nothing ready
            } else if read == available {
                let (context, result) = self.read_error()?;
                local_out.push((non_null_context(context)?, result));
                total_reaped += 1;
            } else {
                return Err(fabric_error(read as i32, "fi_cq_read"));
            }
        }
        Ok(())
    }

    /// Poll the completion queue for remote write completions (`FI_REMOTE_CQ_DATA` entries).
    ///
    /// When a remote endpoint calls `post_out_with_immediate()`, the write generates a completion
    /// entry on this endpoint's CQ with the `FI_REMOTE_CQ_DATA` flag set and the immediate data
    /// in the `data` field. This method returns those immediate data values, allowing the caller
    /// to know which remote writes have landed in their buffer.
    ///
    /// With the `efa` (rxr) provider and "unsolicited write recv" (default on libfabric 1.22+),
    /// no posted receive buffers are needed to receive these completions.
    ///
    /// Returns up to `max` immediate data values from remote write completions.
    ///
    /// NOTE: Prefer `reap_all()` which handles both local and ack completions in one pass.
    /// This method may miss local completions consumed by the same `fi_cq_read`.
    pub fn poll_remote_completions(&self, max: usize) -> Result<Vec<u32>, DmaError> {
        let mut local = Vec::new();
        let mut acks = Vec::new();
        self.reap_all(&mut local, &mut acks, max)?;
        // Discard local completions — caller only wanted acks.
        // This is wasteful; prefer reap_all() for the unified path.
        Ok(acks)
    }

    /// Read one error completion, returning the failing op's `op_context` and the error. `Err` when
    /// the entry the queue promised isn't there, since there is then no op to attribute it to.
    fn read_error(&self) -> Result<(*mut c_void, Result<(), DmaError>), DmaError> {
        let mut entry: fi_cq_err_entry = unsafe { std::mem::zeroed() };
        let read = unsafe { fi_cq_readerr(self.completion_queue, ptr::from_mut(&mut entry), 0) };
        if read <= 0 {
            return Err(fabric_error(read as i32, "fi_cq_readerr"));
        }

        Ok((
            entry.op_context,
            Err(crate::error::completion_error(
                self.completion_queue,
                &entry,
            )),
        ))
    }

    /// The endpoint's local fabric address, to advertise to a peer.
    pub fn local_address(&self) -> Result<Vec<u8>, DmaError> {
        let mut length: usize = 0;
        // The first call discovers the required length, returning -FI_ETOOSMALL.
        unsafe {
            fi_getname(&mut (*self.endpoint).fid, ptr::null_mut(), &mut length);
        }
        if 0 == length {
            return Err(DmaError::Fabric("fi_getname returned zero length".into()));
        }
        let mut address = vec![0u8; length];
        check(
            unsafe {
                fi_getname(
                    &mut (*self.endpoint).fid,
                    address.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            "fi_getname",
        )?;
        address.truncate(length);
        Ok(address)
    }

    /// Insert a peer's advertised address into the address vector once, returning a reusable handle.
    pub fn insert_peer(
        &mut self,
        client_id: u64,
        peer_address: &[u8],
    ) -> Result<Arc<RegisteredAddress>, DmaError> {
        self.peer_addresses.handle(client_id, peer_address)
    }

    /// Let go of a disconnected client's address-vector entry. It leaves the vector only once every
    /// client advertising that address has gone.
    pub fn release_peer(&mut self, client_id: u64) {
        self.peer_addresses.release(client_id);
    }

    /// The address vector its entries live in. Only for tests that run [`PeerAddresses`] against
    /// a real vector.
    #[cfg(test)]
    pub(crate) fn address_vector(&self) -> *mut fid_av {
        self.address_vector
    }

    /// Register a caller-owned span on this endpoint's domain so operands inside it cost no
    /// `fi_mr_reg`. A provider needing no local registration has nothing to pin.
    pub(crate) fn pin_region(&mut self, base: usize, length: usize) -> Result<(), DmaError> {
        if !self.requires_local_mr {
            return Ok(());
        }
        self.local_regions.pin(base, length)
    }

    /// The local descriptor covering an RMA operand. A null descriptor and no registration for tcp
    /// and other providers needing no local registration.
    pub(crate) fn local_operand(
        &mut self,
        pointer: *mut u8,
        length: usize,
        cacheable: impl FnOnce() -> Option<CacheableSpan>,
    ) -> Result<LocalOperand, DmaError> {
        if !self.requires_local_mr {
            return Ok(LocalOperand {
                descriptor: ptr::null_mut(),
                lease: None,
            });
        }
        self.local_regions.operand(pointer, length, cacheable)
    }

    /// Build a connection to an inserted peer. `remote_address` is the peer buffer's virtual address
    /// on `FI_MR_VIRT_ADDR` providers like efa, or 0 where addressing is by offset, like tcp. Makes
    /// no fabric calls, so a session can rebuild one per command.
    pub fn connection(
        &self,
        peer: &RegisteredAddress,
        remote_key: u64,
        remote_address: u64,
    ) -> LibfabricConnection<'_> {
        LibfabricConnection::new(self.endpoint, peer.handle(), remote_key, remote_address)
    }

    /// A snapshot of the selected provider's attributes, for `DMA.INFO`.
    pub fn describe(&self) -> EndpointInfo {
        unsafe {
            let prov_name = (*(*self.info).fabric_attr).prov_name;
            let provider = if prov_name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(prov_name).to_string_lossy().into_owned()
            };
            EndpointInfo {
                provider,
                addr_format: (*self.info).addr_format,
                mr_mode: (*(*self.info).domain_attr).mr_mode as u32,
                caps: (*self.info).caps,
                requires_local_mr: self.requires_local_mr,
                uses_virtual_addressing: self.uses_virtual_addressing,
            }
        }
    }
}

/// A diagnostic snapshot of the libfabric provider an endpoint selected.
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// `fi_fabric_attr.prov_name`, empty if the provider reported none.
    pub provider: String,
    /// `fi_info.addr_format`, the `FI_ADDR_*` format of the endpoint's addresses.
    pub addr_format: u32,
    /// `fi_domain_attr.mr_mode`, the `FI_MR_*` registration bits the provider requires.
    pub mr_mode: u32,
    /// `fi_info.caps`, the capability bits the provider granted.
    pub caps: u64,
    /// `FI_MR_LOCAL`: local operands must be registered, so they go through the region cache.
    pub requires_local_mr: bool,
    /// `FI_MR_VIRT_ADDR`: a peer's remote address is its buffer's virtual address, not an offset.
    pub uses_virtual_addressing: bool,
}

impl EndpointInfo {
    /// Human-readable `field: value` lines.
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("provider: {}", self.provider),
            format!("addr_format: {}", self.addr_format),
            format!(
                "mr_mode: 0x{:x} [{}]",
                self.mr_mode,
                decode_mr_mode(self.mr_mode)
            ),
            format!("caps: 0x{:x} [{}]", self.caps, decode_caps(self.caps)),
            format!("requires_local_mr: {}", self.requires_local_mr),
            format!("uses_virtual_addressing: {}", self.uses_virtual_addressing),
        ]
    }
}

fn decode_mr_mode(mr_mode: u32) -> String {
    let flags = [
        (FI_MR_LOCAL, "LOCAL"),
        (FI_MR_VIRT_ADDR, "VIRT_ADDR"),
        (FI_MR_ALLOCATED, "ALLOCATED"),
        (FI_MR_PROV_KEY, "PROV_KEY"),
        (FI_MR_ENDPOINT, "ENDPOINT"),
        (FI_MR_HMEM, "HMEM"),
    ];
    flags
        .iter()
        .filter(|(bit, _)| mr_mode & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

fn decode_caps(caps: u64) -> String {
    let flags = [
        (FI_MSG, "MSG"),
        (FI_RMA, "RMA"),
        (FI_READ, "READ"),
        (FI_WRITE, "WRITE"),
        (FI_REMOTE_READ, "REMOTE_READ"),
        (FI_REMOTE_WRITE, "REMOTE_WRITE"),
    ];
    flags
        .iter()
        .filter(|(bit, _)| caps & u64::from(*bit) != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

impl Drop for LibfabricEndpoint {
    fn drop(&mut self) {
        use crate::sys::fi_close;
        // The local memory regions are domain objects, so they must close before the domain. The
        // worker has joined, so no in-flight op still holds an Rc clone.
        self.local_regions.clear();
        // Each entry removes itself from the address vector when its last holder drops, so they all
        // have to go before that vector is closed below.
        self.peer_addresses.clear();
        unsafe {
            // Close the ack buffer MR before the domain — it's a domain object.
            if !self.ack_buffer_mr.is_null() {
                fi_close(&mut (*self.ack_buffer_mr).fid);
            }
            if !self.endpoint.is_null() {
                fi_close(&mut (*self.endpoint).fid);
            }
            if !self.completion_queue.is_null() {
                fi_close(&mut (*self.completion_queue).fid);
            }
            if !self.address_vector.is_null() {
                fi_close(&mut (*self.address_vector).fid);
            }
            if !self.domain.is_null() {
                fi_close(&mut (*self.domain).fid);
            }
            if !self.fabric.is_null() {
                fi_close(&mut (*self.fabric).fid);
            }
            if !self.info.is_null() {
                fi_freeinfo(self.info);
            }
        }
        // The ack_buffer Box is dropped automatically after this, which is fine since
        // the MR is already closed.
    }
}
