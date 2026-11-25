//! JSON-RPC 1.0 envelope handling, independent of HTTP and domain methods.
use crate::Error;
use planchet_transport::{Request, Transport};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug)]
pub struct ClientConfig {
    pub max_response_bytes: usize,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: 64 * 1024 * 1024,
        }
    }
}
pub struct Client<T> {
    transport: T,
    next_id: Arc<AtomicU64>,
    config: ClientConfig,
}
impl<T: Clone> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            next_id: self.next_id.clone(),
            config: self.config,
        }
    }
}
impl<T> fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self::with_config(transport, ClientConfig::default())
    }
    pub fn with_config(transport: T, config: ClientConfig) -> Self {
        Self {
            transport,
            next_id: Arc::new(AtomicU64::new(1)),
            config,
        }
    }
    /// Sends exactly one request; transport implementations must honor the no-replay contract.
    /// `params` must serialize to an array (Core 1.0 positional arguments).
    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, Error> {
        self.call_with_response_limit(method, params, self.config.max_response_bytes)
            .await
    }
    /// Explicit per-call budget, still bounded by the injected transport's own ceiling.
    pub async fn call_with_response_limit<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
        max_response_bytes: usize,
    ) -> Result<R, Error> {
        if max_response_bytes == 0 {
            return Err(Error::InvalidResponse {
                method: method.into(),
                reason: "response budget must be positive",
            });
        }
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::RequestIdExhausted)?;
        #[derive(Serialize)]
        struct Envelope<'a, P> {
            jsonrpc: &'static str,
            id: u64,
            method: &'a str,
            params: P,
        }
        let params = serde_json::value::to_raw_value(&params)
            .map_err(|_| invalid(method, "request serialization failed"))?;
        if !params.get().starts_with('[') {
            return Err(invalid(method, "params must be an array"));
        }
        let body = serde_json::to_vec(&Envelope {
            jsonrpc: "1.0",
            id,
            method,
            params,
        })
        .map_err(|_| invalid(method, "request serialization failed"))?;
        let response = self
            .transport
            .send(Request {
                body,
                max_response_bytes,
            })
            .await
            .map_err(Error::Transport)?;
        // Enforce this again for injected transports, before even attempting JSON parsing.
        if response.body.len() > max_response_bytes {
            return Err(Error::Transport(
                planchet_transport::Error::ResponseTooLarge {
                    limit: max_response_bytes,
                },
            ));
        }
        #[derive(Deserialize)]
        struct Reply {
            id: u64,
            result: Box<RawValue>,
            error: Box<RawValue>,
        }
        let reply: Reply = match serde_json::from_slice(&response.body) {
            Ok(reply) => reply,
            Err(_) if !(200..300).contains(&response.status) => {
                return Err(Error::HttpStatus {
                    status: response.status,
                });
            }
            Err(_) => return Err(invalid(method, "malformed or incomplete JSON-RPC envelope")),
        };
        if reply.id != id {
            return Err(invalid(method, "response id does not match request"));
        }
        if reply.error.get() != "null" {
            if reply.result.get() != "null" {
                return Err(invalid(method, "both result and error are non-null"));
            }
            #[derive(Deserialize)]
            struct Fault {
                code: i64,
                message: String,
                #[serde(default)]
                data: Option<Box<RawValue>>,
            }
            let fault: Fault = serde_json::from_str(reply.error.get())
                .map_err(|_| invalid(method, "malformed RPC error"))?;
            return Err(Error::Rpc {
                method: method.into(),
                code: fault.code,
                message: fault.message,
                data: fault.data,
                status: response.status,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(Error::HttpStatus {
                status: response.status,
            });
        }
        serde_json::from_str(reply.result.get())
            .map_err(|_| invalid(method, "result does not match the requested type"))
    }
}
fn invalid(method: &str, reason: &'static str) -> Error {
    Error::InvalidResponse {
        method: method.into(),
        reason,
    }
}
