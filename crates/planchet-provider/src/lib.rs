//! Dogecoin Core JSON-RPC 1.0 reader. Nothing retries or broadcasts implicitly.
#![forbid(unsafe_code)]
pub mod client;
mod provider;
mod verify;
pub mod wallet;
pub use client::{Client, ClientConfig};
use planchet_primitives::{BlockHash, Network, Txid};
pub use planchet_rpc_types as types;
pub use planchet_transport as transport;
pub use provider::{Provider, UtxoObservation, UtxoStatus, UtxoUnknown};
use serde_json::value::RawValue;
use std::fmt;
pub use verify::{BlockCheck, check_raw_block};
pub use wallet::{SnapshotLimits, UnspentSnapshot};

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Transport(transport::Error),
    Rpc {
        method: String,
        code: i64,
        message: String,
        data: Option<Box<RawValue>>,
        status: u16,
    },
    HttpStatus {
        status: u16,
    },
    InvalidResponse {
        method: String,
        reason: &'static str,
    },
    RequestIdExhausted,
    NetworkMismatch {
        expected: Network,
        chain: String,
        genesis: BlockHash,
    },
    HashMismatch {
        expected: BlockHash,
        actual: BlockHash,
    },
    AnchorChanged {
        height: u64,
        before: BlockHash,
        after: BlockHash,
    },
    TipChanged {
        before: BlockHash,
        after: BlockHash,
    },
    InvalidBlock {
        reason: &'static str,
    },
    BroadcastTxidMismatch {
        expected: Txid,
        actual: Txid,
    },
    /// Bytes may have reached the node. Reconcile by txid; no replay has been attempted.
    SubmissionUnknown {
        txid: Txid,
        cause: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => e.fmt(f),
            Self::Rpc {
                method,
                code,
                message,
                ..
            } => write!(f, "{method}: Core error {code}: {message}"),
            Self::HttpStatus { status } => write!(f, "RPC HTTP status {status}"),
            Self::InvalidResponse { method, reason } => write!(f, "{method}: {reason}"),
            Self::RequestIdExhausted => f.write_str("RPC request IDs exhausted"),
            Self::NetworkMismatch {
                expected,
                chain,
                genesis,
            } => write!(
                f,
                "expected {expected}, node reports chain {chain} with genesis {genesis}"
            ),
            Self::HashMismatch { expected, actual } => {
                write!(f, "requested block {expected}, decoded {actual}")
            }
            Self::AnchorChanged {
                height,
                before,
                after,
            } => write!(f, "height {height} changed from {before} to {after}"),
            Self::TipChanged { before, after } => {
                write!(f, "chain tip changed from {before} to {after}")
            }
            Self::InvalidBlock { reason } => write!(f, "block check failed: {reason}"),
            Self::BroadcastTxidMismatch { expected, actual } => {
                write!(f, "submitted {expected}, node returned {actual}")
            }
            Self::SubmissionUnknown { txid, cause } => {
                write!(f, "submission outcome unknown for {txid}: {cause}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::SubmissionUnknown { cause, .. } => Some(cause),
            _ => None,
        }
    }
}
