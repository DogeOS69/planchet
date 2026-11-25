# planchet-transport

Host/std transport seam for Rust 2024 / MSRV 1.91. Project release license
is pending. Default features are empty. `http` enables pinned reqwest
0.12.28 with `default-features = false` and no additional reqwest features.
Tokio supplies asynchronous deadlines and concurrency permits. TLS is absent.

Implement `Transport::send(Request) -> TransportFuture<'_>` for application or
mock transports. `Arc<dyn Transport>` works with `Client<T>`/`Provider<T>` via the
Arc forwarding implementation. Implementations must enforce the request's
response-byte cap and must not replay requests. No type contains a domain RPC
method or depends on the provider.

`HttpTransport::new(endpoint, Option<BasicAuth>, HttpConfig)` accepts only
explicit HTTP endpoints with no userinfo/query/fragment. Wallet paths are
allowed. Basic auth is sent in a sensitive Authorization header, and its username
cannot contain a colon. Credentials, endpoint, and request/response bodies are
omitted from Debug. reqwest errors, which can contain endpoint URLs, are reduced
to redacted I/O/timeout categories. The library emits no logs.

HTTP uses POST with JSON content type, HTTP/1 only, no redirects, no proxy
discovery, and an explicit never-retry policy. Compression and TLS features are
not enabled. HTTPS is rejected before any request; it is never rewritten to HTTP.
The scheme check remains in force even if a downstream workspace unifies extra
reqwest features. See the upstream
[ClientBuilder documentation](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html)
for the reqwest redirect/retry controls this implementation configures explicitly.

The default cap is 64 MiB with 8 concurrent requests, a 10-second connect timeout,
and a 60-second total timeout. Configuration must use positive limits/deadlines.
The total deadline covers semaphore queueing, connect, headers and the full body.
The smaller of request-specific and transport-wide body limits applies. Declared
Content-Length and streamed chunks are checked before extending the body buffer.
A cancellation or timeout cannot reverse an RPC already received by the node.
Applications own retries and reconciliation.

## Qualification recorded on 2026-11-24

For `aarch64-apple-darwin`, Rust 1.91.0, the selected
`planchet-provider --features http` graph including normal/build/dev edges had
**93 unique packages** (including the five workspace packages). Target-filtered
metadata/tree inspection found no native `links`, Git sources, native sys/TLS/
crypto packages or native build helpers, and no bundled C/C++/assembly/objects in
the selected package sources. All 11 selected build scripts were reviewed for
native build/link directives; command invocations were Rust compiler/version
probes on this target. No third-party TLS backend or native crypto is selected.
System ABI bindings such as libc/socket2/mio contain Rust referring to the target
platform runtime; they do not compile a third-party C implementation.

A fresh-target `cargo +1.91.0 build -p planchet-provider --features http
--example verify-block --locked --message-format=json` succeeded with
`CC=/usr/bin/false CXX=/usr/bin/false AR=/usr/bin/false`. Its 11 executed build
scripts emitted **zero native link libraries and zero native search paths**.
`otool -L` on the example showed only platform libSystem and libiconv, with no
third-party native libraries. The resulting binary successfully checked the
434-byte Core regtest AuxPoW fixture offline against its independently recorded
ID and Merkle root.

This records the examined host/profile; it is not a claim of TLS support,
all-target qualification, or a sandbox against malicious build scripts ignoring
compiler environment variables. Repeat the source/feature audit and clean build
when changing dependencies or supported targets. The root dependency-policy
script supplies the repository-wide repeatable static screen.

Provider's HTTP suite drives real localhost sockets and covers envelopes,
chunked/declared/exact-boundary body limits, timeouts, Basic auth/redaction,
redirect refusal, and no broadcast replay. Its fake servers restore blocking
mode explicitly on accepted macOS sockets and use finite I/O timeouts.
