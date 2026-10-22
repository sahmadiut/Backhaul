# Optional ECH in Backhaul v1.1.1

ECH hides the tunnel hostname inside the TLS handshake. The server IP and outer
public hostname remain visible. It does not guarantee that a connection bypasses
filtering. ECH is **off by default**; existing configurations retain their behavior.
In this release ECH is supported with `transport = "https"` only. Other transports
reject `ech = true` at startup instead of silently ignoring it.

## Direct connection: simplest setup (no CDN)

Use v1.1.1 on both machines. Choose two DNS names, for example
`tunnel.example.com` (private inner name) and `public.example.com` (visible name).
You can use names under your own domain. With `edge_ip`, no public DNS record or
public certificate authority is needed for this direct setup.

On the server, generate the files once:

```sh
./backhaul -ech-generate /etc/backhaul/ech -ech-name tunnel.example.com -ech-public-name public.example.com
```

The parent `/etc/backhaul` must already exist. The destination directory must be
new: the command refuses to replace existing credentials. It creates a certificate
valid for one year and ECH keys. Keep `key.pem` and `ech-key.json` on the server.
Copy **only** `cert.pem` and `ech-config.txt` securely to `/etc/backhaul/ech/` on
the client. Never copy private keys to the client.

Example complete server configuration (`server.toml`):

```toml
[server]
bind_addr = "0.0.0.0:443"
transport = "https"
token = "REPLACE-WITH-A-LONG-RANDOM-SHARED-SECRET"
ports = ["8080=127.0.0.1:8080"]
tls_cert = "/etc/backhaul/ech/cert.pem"
tls_key = "/etc/backhaul/ech/key.pem"
ech = true
ech_key = "/etc/backhaul/ech/ech-key.json"
```

Example complete client configuration (`client.toml`):

```toml
[client]
remote_addr = "tunnel.example.com:443"
edge_ip = "203.0.113.10" # Replace with the actual SERVER IP
transport = "https"
token = "REPLACE-WITH-A-LONG-RANDOM-SHARED-SECRET"
ech = true
ech_config = "/etc/backhaul/ech/ech-config.txt"
ech_ca = "/etc/backhaul/ech/cert.pem"
```

Use the same token on both sides. The example forwards server port 8080 to
127.0.0.1:8080 on the client; replace `ports` with your existing mappings.
`remote_addr` must match the generated inner name, even when connecting by IP.
Start each side as usual:

```sh
./backhaul -c server.toml
./backhaul -c client.toml
```

If you already have working HTTPS settings, keep them and add the ECH fields.
You may keep your existing publicly trusted certificate instead of the generated
certificate; it should cover the inner and outer names. Omit `ech_ca` when using
a publicly trusted certificate. Paths are relative to the process working directory
unless absolute paths are used; absolute paths are recommended for services.

## With a CDN or reverse proxy

**Check compatibility first:** the TLS terminator must support ECH and forward
HTTP/1.1 `101 Upgrade: backhaul` on `/channel` and `/tunnel/*`, preserving the
Authorization header and bidirectional stream. Normal website hosting or WebSocket
support alone is insufficient. `httpsws` still uses a custom control upgrade and
is not an ECH workaround in this release. Cloudflare publishing ECH records does
not establish that its ordinary proxy can forward this transport.

For a compatible ECH-terminating CDN, enable ECH in the provider's settings and
use its proxied hostname with a valid certificate. Use this client configuration:

```toml
[client]
remote_addr = "tunnel.example.com:443"
transport = "https"
token = "REPLACE-WITH-YOUR-EXISTING-SHARED-SECRET"
ech = true
```

Without `ech_config`, the client automatically reads the hostname's DNS HTTPS
record through `https://cloudflare-dns.com/dns-query` using authenticated HTTPS.
It caches the result for up to one minute. No public ECH record means a clear
connection error, never a silent non-ECH connection. Discovery currently supports
an ECH parameter directly present in the returned HTTPS records; HTTPS AliasMode
chains are not followed. A provider-supplied base64 ECHConfigList file can be used
with `ech_config` if automatic discovery is unsuitable.

Optional client settings:

```toml
# Use another trusted DNS JSON service that returns HTTPS records:
ech_doh = "https://dns.google/resolve"
# Pin the connection to a chosen CDN edge while retaining the hostname:
edge_ip = "203.0.113.20"
```

DoH protects the ECH record lookup. Destination address lookup still uses the
system resolver unless `edge_ip` is set; use encrypted system DNS if needed.
The DoH provider sees your queries. TLS still authenticates the tunnel endpoint.

At the origin, retain the existing working CDN-to-Backhaul configuration and
leave `ech = false` (or omit it): the CDN owns the public-facing ECH keys.
The CDN-to-origin TLS connection is separate and is not protected by client ECH.
For a TCP passthrough proxy, use the **direct** setup instead: Backhaul terminates
ECH and the client needs Backhaul's public ECH configuration.

## Errors, renewal, and turning it off

- `no ECH HTTPS record`: enable ECH at the CDN, use its correct hostname, or use
  the direct setup with `ech_config`.
- Certificate verification error: check the hostname, system clock, certificate
  expiry, and `ech_ca`. ECH does not inherit legacy skip-verification behavior.
- ECH rejection: check matching direct key/config files. For CDN rotation,
  discovery refreshes within one minute. There is no retry without ECH and no
  automatic adoption of server retry configurations.
- HTTP response other than 101: check the token and proxy upgrade support.
- Before the direct certificate expires, generate a new directory, distribute
  the new public files, update both configurations, and restart both sides during
  a maintenance window. Rotation is manual and may interrupt connections; this
  version does not implement overlapping-key rotation.
- To disable ECH, set `ech = false` on the client and server. Keep the working
  HTTPS certificate settings. An ECH-enabled server also accepts legacy clients;
  privacy enforcement is on clients configured with `ech = true`.

Use Go **1.26.10 or newer** to build this release; the release workflow uses
Go 1.27.3. Setup files contain secrets: protect the generated directory and avoid
committing it. On Windows, apply appropriate filesystem ACLs; Unix mode bits do
not configure Windows ACLs.

References: [Go TLS ECH API](https://pkg.go.dev/crypto/tls#Config),
[Cloudflare ECH documentation](https://developers.cloudflare.com/ssl/edge-certificates/ech/).
