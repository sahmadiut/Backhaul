# HTTP/HTTPS performance, recovery, and ECH review

Reviewed on 2026-10-22. Scope: `transport = "http"` and `"https"`.
The separate `httpws`/`httpsws` lifecycle has not been rewritten. Shared dialer
and TCP relay improvements also apply to their callers.

## Implemented changes

- Independent connection generations replace in-place restart mutation. Each
  generation closes its registered control, idle, queued, and active sockets,
  joins its workers, and releases listeners before the next run starts.
- The usage monitor stays alive across reconnects, retaining counters and avoiding
  repeated monitor port binding. HTTP status updates synchronize with stats reads.
- The client maintains idle plus in-flight pool slots, repairs failed slots every
  second, and replenishes immediately when a tunnel is assigned. Spare-pool growth
  is capped at four times `connection_pool`; active forwarded streams are not
  subject to this cap. The adaptive target uses recent demand and
  `aggressive_pool`; excess spare connections retire as they are consumed.
- Server control reads time out after three heartbeat intervals. Client control
  inactivity times out after `heartbeat_timeout` (default 180 seconds). Control
  writes, HTTP upgrade writes, and tunnel assignment writes have deadlines.
- Cancellation interrupts stalled HTTP upgrades even with no handshake timeout.
  DNS resolution now takes place inside `DialContext`, so its timeout and
  cancellation cover remote-host lookup and alternate-address dialing.
- Transient listener failures trigger retry instead of exiting the process.
- HTTPS uses 16 KiB relay buffers in both directions, including connections wrapped
  to retain payload following an upgrade response. Application relay buffers drop
  from typically 80 KiB to 32 KiB per active HTTPS connection (48 KiB saved).
  This excludes TLS state, kernel socket buffers, goroutines, and pool retention.
- Disabled trace logging no longer boxes byte counts on every relay iteration.
  The relay preserves final bytes returned alongside EOF and stops on zero-length
  writes. Both copy directions finish before their session worker returns.
- Existing Linux TCP splice, HTTP request/response buffer pools, TLS session
  caching, tokens, paths, and the binary tunnel protocol remain in use.

Recovery establishes fresh connections. An interrupted application TCP stream
cannot resume its previous byte stream; the application must reconnect.

## Configuration

Existing configuration files continue to load. With the default server
`heartbeat = 40`, the server detects missing acknowledgements after roughly
120 seconds; the client defaults to 180 seconds of control inactivity.
Detection is followed by cleanup, retry delay, and connection establishment.

For faster detection on a reasonably stable link, an example is:

```toml
# Server configuration
[server]
heartbeat = 10
```

```toml
# Client configuration
[client]
heartbeat_timeout = 40
retry_interval = 3
connection_pool = 8
aggressive_pool = false
```

These are additions to the normal configuration, not complete configuration
files. Keep the client timeout at least three times the server heartbeat.
If a deployment uses unusually long heartbeat intervals, increase the client
timeout accordingly. Tight timeouts can cause reconnects during congestion.

## Validation and measurements

Regression coverage includes real HTTP and HTTPS echo transfers, three successive
client/server restart cycles for each mode, closure of interrupted streams,
missing and acknowledged heartbeats, silent control peers, repair of closed idle
pool connections without server requests, cancellation of a stalled HTTP upgrade,
bounded assignment writes, concurrent socket registration during shutdown, final
payload preservation, and zero-progress writes.

The four changed transport/network/handler packages pass Go's race detector.
The host is Windows with Go 1.23.1; the repository's existing Linux socket code
does not compile natively on Windows. Tests used temporary Go overlays adapting
socket handle types and providing the otherwise Linux-only listener symbol.
No repository platform shim was added. The HTTP tests use real Windows loopback
sockets; they do not establish Linux socket-option or splice runtime behavior.
Linux/amd64 `go vet ./...` and the application cross-build pass without overlays.

The new `BenchmarkHTTPSRelay` uses real TLS over `net.Pipe`. Three one-second
runs on this host compared the original relay against the modified relay:

| Measurement | Original | Modified |
| --- | --- | --- |
| Local-to-TLS relay buffer | 65,536 bytes | 16,384 bytes |
| Allocations per 64 KiB | 6 | 4 |
| Allocated bytes per 64 KiB | 114–117 | 99–100 |
| Throughput | 2.12–2.19 GB/s | 2.16–2.22 GB/s |

The throughput ranges are similar; they do not demonstrate a material WAN speed
increase. Reduced buffer retention and allocations are the measured improvements.
Process RSS under production concurrency, Linux runtime tests, loss/latency
injection, long-duration soak tests, and deployment have not been performed.

On Linux, run:

```sh
go test -race ./internal/utils/network ./internal/utils/handlers ./internal/client/transport ./internal/server/transport
go test ./internal/utils/handlers -run '^$' -bench BenchmarkHTTPSRelay -benchmem -count=3
go vet ./...
```

## ECH: meaning and fit for this project

Encrypted Client Hello (ECH) encrypts the sensitive inner TLS ClientHello,
including the requested server name (SNI). The outer ClientHello and its public
name remain visible. It protects hostname privacy from passive observers; it
does not hide the destination IP, packet timing, traffic volume, or the use of
TLS. Plaintext DNS can still reveal the hostname, and a dedicated IP can identify
the service. ECH is a privacy feature, not a speed or recovery feature and not a
guarantee of bypassing filtering. See [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html).

## v1.1.1: optional ECH implementation

ECH is now an opt-in feature for `transport = "https"`. See the
[step-by-step direct and CDN setup guide](ech.md) for complete configurations.

- `ech = true` enables authenticated TLS 1.3 ECH on the client; failures never
  fall back to an exposed inner SNI. Both control and tunnel sockets use it.
- Direct servers use generated ECH keys and a pinned certificate with a single
  `-ech-generate` command. Existing files are never overwritten.
- Compatible CDN deployments can discover ECH through authenticated DNS over
  HTTPS, or use a provisioned config file. CDN support for the custom Backhaul
  upgrade is still required; ordinary HTTPS/WebSocket proxying is insufficient.
- Existing configurations keep their original behavior. Server ECH remains
  compatible with non-ECH clients. ECH is rejected for unsupported transports.
- Go 1.26.10 is now the minimum build toolchain; release CI uses Go 1.27.3.

ECH hides the inner TLS name, not the destination IP, traffic shape, or outer
name. Address resolution can still expose names unless a pinned `edge_ip` or
an encrypted system resolver is used. Direct key/certificate rotation is manual;
CDN discovery refreshes within one minute. No production CDN compatibility or
Linux runtime acceptance is implied by local tests.
## v1.1.1 validation

- Real TLS tests confirm ECH acceptance, rejection without fallback, and failure
  with an untrusted certificate. Tests also cover DoH parsing/cancellation,
  malformed configuration, safe generation, TOML fields, and unsupported modes.
- The HTTP recovery test now includes an ECH variant with real forwarding and
  three server/client restart cycles, alongside unchanged HTTP and HTTPS cases.
- Race-detector checks pass for the ECH, network, handler, and client/server
  transport packages. Configuration and startup-validation tests pass as well.
- Linux/amd64 `go vet ./...` and application cross-build pass with Go 1.26.10.
- Windows runtime tests use temporary socket/listener compatibility overlays;
  CLI/version/generation checks additionally stub the Linux-only tuning function.
  The CLI reports v1.1.1 and generates the expected credential files. These
  overlays are outside the repository and do not establish Linux runtime behavior.
- No live CDN deployment, hosted release, or production rollout was performed.
