use super::*;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct BasicAuth {
    username: String,
    password: String,
}
impl BasicAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}
impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BasicAuth([REDACTED])")
    }
}
#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub connect_timeout: Duration,
    /// Covers queueing for a concurrency permit, connection, headers and the entire body.
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_in_flight: usize,
}
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            max_response_bytes: 64 * 1024 * 1024,
            max_in_flight: 8,
        }
    }
}
/// HTTP only. Endpoints must be explicitly configured on a trusted connection.
/// Redirects, proxy discovery, compression, TLS and automatic retries are disabled.
#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    auth: Option<BasicAuth>,
    config: HttpConfig,
    permits: Arc<Semaphore>,
}
impl fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpTransport")
            .field("endpoint", &"[REDACTED]")
            .field("auth", &self.auth)
            .field("config", &self.config)
            .finish()
    }
}
impl HttpTransport {
    pub fn new(endpoint: &str, auth: Option<BasicAuth>, config: HttpConfig) -> Result<Self, Error> {
        let endpoint = reqwest::Url::parse(endpoint)
            .map_err(|_| Error::InvalidConfiguration("invalid endpoint URL"))?;
        if endpoint.scheme() != "http" {
            return Err(Error::UnsupportedScheme);
        }
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::InvalidConfiguration(
                "endpoint must have a host and no userinfo, query or fragment; use BasicAuth",
            ));
        }
        if config.max_in_flight == 0
            || config.max_in_flight > Semaphore::MAX_PERMITS
            || config.max_response_bytes == 0
            || config.request_timeout.is_zero()
            || config.connect_timeout.is_zero()
        {
            return Err(Error::InvalidConfiguration(
                "limits and deadlines must be positive and concurrency within semaphore capacity",
            ));
        }
        if auth.as_ref().is_some_and(|a| a.username.contains(':')) {
            return Err(Error::InvalidConfiguration(
                "Basic authentication username cannot contain a colon",
            ));
        }
        let client = reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| Error::InvalidConfiguration("HTTP client initialization failed"))?;
        let permits = Arc::new(Semaphore::new(config.max_in_flight));
        Ok(Self {
            client,
            endpoint,
            auth,
            config,
            permits,
        })
    }
    async fn execute(&self, request: Request) -> Result<Response, Error> {
        if request.max_response_bytes == 0 {
            return Err(Error::InvalidConfiguration(
                "response limit must be positive",
            ));
        }
        let limit = request
            .max_response_bytes
            .min(self.config.max_response_bytes);
        let _permit = self.permits.acquire().await.map_err(|_| Error::Io)?;
        let mut builder = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.body);
        if let Some(auth) = &self.auth {
            builder = builder.basic_auth(&auth.username, Some(&auth.password));
        }
        let mut response = builder.send().await.map_err(map_error)?;
        let status = response.status().as_u16();
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(Error::ResponseTooLarge { limit });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(Error::ResponseTooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response { status, body })
    }
}
fn map_error(error: reqwest::Error) -> Error {
    // reqwest errors include the endpoint URL; never retain or format them.
    if error.is_timeout() {
        Error::Timeout
    } else {
        Error::Io
    }
}
impl Transport for HttpTransport {
    fn send(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move {
            tokio::time::timeout(self.config.request_timeout, self.execute(request))
                .await
                .map_err(|_| Error::Timeout)?
        })
    }
}
