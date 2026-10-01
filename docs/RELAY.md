# Egress relay (`vprox relay`)

The relay is the vprox side of the macOS static-IP dataplane. On a macOS
host, pf `rdr` steers each static-IP VM's off-subnet TCP and UDP to a proxy
that runs inside the Blacksmith agent (`agent/egressproxy` in
FastActions/fa); a small root `pf-helper` child per VM performs the two
privileged pf ioctls and opens the relay connection on the agent's behalf.
The proxy holds **one TLS 1.3 connection per VM** to the relay and
multiplexes that VM's flows over it with yamux. The relay dials every
destination from the static IP the session was granted, so the VM's egress
address is the static IP without any tunnel or `route-to`.

```
VM -> pf rdr -> egressproxy (inside the mac agent; root pf-helper for NATLOOK/state kill/dial)
   -> TLS 1.3 + yamux, one session per VM -> vprox relay -> bind(static_ip) -> destination
```

## Running

```
VPROX_PASSWORD=... vprox relay \
  --listen 0.0.0.0:9443 \
  --allow-source 205.234.200.0/24 \
  --deny-cidr 10.100.0.0/16 --deny-cidr 10.0.0.0/24 \
  --metrics-addr 127.0.0.1:9444
```

* `--allow-source` is required; connections from other sources are dropped
  before the TLS handshake. Use the same CIDRs as the `/connect-ipip` UFW rule.
* The TLS certificate defaults to the embedded vprox certificate. The host
  proxy does not verify it against a CA; instead both ends prove knowledge of
  `VPROX_PASSWORD` over the TLS channel (HMAC-SHA256 of the TLS exporter
  value `EXPORTER-blacksmith-relay`, client and server roles). The password
  never crosses the wire and a proof cannot be replayed on another
  connection; a relay without the password is refused by the host proxy.
* SIGTERM drains: the listener closes, every session gets a yamux GoAway so
  the host proxy reconnects, and open streams get `--drain-timeout` to finish.

## Destination policy

The relay dials as a local process, so the FORWARD-chain rules that guard the
IPIP path do not apply. Every stream is checked before dialling; refusals are
reported to the host proxy with `StreamPolicyDenied` and counted in
`vprox_relay_streams_refused_total{status="policy_denied"}`.

Always denied: `0.0.0.0/8`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`),
`100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`,
`240.0.0.0/4`, IPv6, port 0, and every address currently assigned to one of
the relay host's interfaces (refreshed every 10s, so new static IPs and
tunnel addresses are covered without a restart). `--deny-cidr` and
`--deny-port` add to that list; pass the WireGuard block and the internal
network CIDR.

## Limits

| flag | default | refusal |
|---|---|---|
| `--max-sessions` | 4096 | `HelloSessionLimit` |
| `--max-sessions-per-source` | 64 | `HelloSessionLimit` |
| `--max-streams-per-session` | 4096 | `StreamLimit` |
| `--max-udp-per-session` | 1024 | `StreamUDPLimit` |
| `--stream-window` | 256 KiB | (yamux receive window) |
| `--dial-timeout` | 5s | `StreamDialFailed` |
| `--tcp-idle` | 6h | stream closed |
| `--udp-idle` | 60s | stream closed |
| `--drain-timeout` | 15s | streams cut on shutdown |

The hello must arrive within 10s of the TCP accept.

## Metrics (`--metrics-addr`, default `127.0.0.1:9444`)

`vprox_relay_sessions_open`, `vprox_relay_sessions_total`,
`vprox_relay_hello_refused_total{status}`, `vprox_relay_streams_open{proto}`,
`vprox_relay_streams_total{proto}`, `vprox_relay_streams_refused_total{status}`,
`vprox_relay_bytes_total{dir,static_ip}`, `vprox_relay_dial_seconds{proto}`,
`vprox_relay_source_rejected_total`, `vprox_relay_draining`.

## Wire protocol v1 (`lib/relayproto`)

All integers big-endian. The same package, with identical hex fixtures,
lives in FastActions/fa as `agent/egressproxy/relayproto`; the fixtures are
the compatibility contract between the two modules.

```
client hello   "BRLY" | u8 version=1 | u16 len | JSON {"auth","vm_id","static_ip"}
server reply   u8 status | u16 len | JSON {"egress_ip"} or {"error"}
   status: 0 ok, 1 unauthorized, 2 bad_static_ip, 3 session_limit,
           4 protocol_error, 5 unavailable
-- yamux from here; each stream: --
stream header  u8 proto (6=TCP, 17=UDP) | 4B IPv4 dst | u16 dst port
stream reply   u8 status | u32 dial duration (us)
   status: 0 ok, 1 dial_failed, 2 policy_denied, 3 limit, 4 udp_limit,
           5 bad_header, 6 unavailable
TCP payload    raw bytes; yamux FIN = half-close in that direction
UDP payload    repeated: u16 len | datagram (len <= 65535, 0 allowed)
```

The hello JSON is capped at 4096 bytes. The static IP in the hello must be
an address of the relay host or the session is refused with `bad_static_ip`;
the reply's `egress_ip` is the address the relay binds outbound sockets to.
