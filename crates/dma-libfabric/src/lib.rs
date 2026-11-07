//! Tools for building servers over the OFI (libfabric) C API.
//!
//! `LibfabricEndpoint` opens a local `FI_EP_RDM` endpoint; `FabricService` runs the worker that
//! posts one-sided RMA against a client's exposed buffer and reaps completions. The peer address and
//! remote key arrive out-of-band, on the caller's own control channel, per request. Clients are
//! passive targets and live outside this crate.
//!
//! [`asynchronous`] is the same server with futures in place of a completion hook.
#![warn(missing_docs)]

pub mod asynchronous;
mod configuration;
mod connection;
mod devices;
mod endpoint;
mod error;
mod local_regions;
mod memory_region;
mod operands;
mod peer_addresses;
mod pool;
mod region_cache;
mod reply;
mod server;
mod server_dma_worker;
mod sys;

pub use configuration::{Configuration, Provider};
pub use devices::discover_domains;
pub use endpoint::{AckBufferInfo, EndpointInfo, LibfabricEndpoint, ACK_MAGIC};
pub use memory_region::MemoryRegion;
pub use operands::{CacheableSpan, Operands};
pub use peer_addresses::RegisteredAddress;
pub use pool::Pool;
pub use region_cache::invalidate;
pub use server::{
    BatchCompleter, Completion, Direction, FabricService, Outcome, TransferDone, TransferRequest,
};
