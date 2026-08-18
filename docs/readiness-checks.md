# Vprox readiness checks

Vprox reports process liveness separately from the readiness of each configured bind IP. The periodic heartbeat shows that the process is reporting, `/health/live` shows that the HTTPS listener is serving, and readiness shows whether the server's local networking prerequisites are intact and whether it can accept another peer.

## Local checks

Each vprox server runs a read-only readiness check immediately after its HTTPS listener starts and every 30 seconds thereafter. The check verifies that:

- the HTTPS listener is active;
- the expected WireGuard interface is up, has the configured address, public key, and listen port, and can be queried through `wgctrl`;
- the bind interface is up and owns the configured static IP;
- an IPv4 default route exists through the bind interface;
- IPv4 forwarding is enabled;
- every forwarding, NAT, and MSS iptables rule installed by vprox exists; and
- the peer address pool has capacity.

The check reads kernel and in-memory state. It does not create peers, send traffic, or repair networking.

## Readiness state

The latest result is cached in memory and includes a status, stable reason, check time, last successful check time, check duration, and consecutive failure count.

The possible statuses are:

- `starting`: no readiness check has succeeded yet;
- `healthy`: the checks are passing and any recovery threshold has been satisfied;
- `degraded`: the server remains eligible after fewer than three failures, or while recovering from a degraded state;
- `unhealthy`: three consecutive checks failed, server setup or the HTTPS listener failed, or the first recovery check succeeded after exclusion; and
- `stale`: no check completed within 75 seconds.

`degraded` remains ready to absorb transient failures. An `unhealthy` or `stale` server requires two consecutive successful checks to become `healthy` again. A server is never ready before its first successful check.

Readiness reasons are stable, low-cardinality values:

- `starting`
- `recovering`
- `listener_unavailable`
- `wireguard_unavailable`
- `bind_interface_invalid`
- `bind_address_missing`
- `default_route_invalid`
- `ipv4_forwarding_disabled`
- `iptables_rule_missing`
- `peer_capacity_exhausted`
- `readiness_check_stale`
- `server_setup_failed`

Detailed system errors are written to local logs and are not included in readiness responses or heartbeat payloads.

## Health endpoints

The existing HTTPS listener serves two health routes:

- `GET /health/live` returns `200` with `{"status":"alive"}` while the listener is serving.
- `GET /health/ready` returns the cached readiness snapshot with no synchronous network inspection or mutation.

`/health/ready` returns `200` for `healthy` and `degraded`, and `503` for `starting`, `unhealthy`, and `stale`. Both successful health responses use `Cache-Control: no-store`.

## Backend heartbeat

The existing `/api/admin/staticip/liveness` heartbeat retains its `ip` and `region` fields and includes a nested `readiness` object for each configured bind IP. Heartbeats continue while a running server is degraded or unhealthy. If setup or the listener fails before the next periodic heartbeat, vprox sends the terminal classified state once before exiting.

The backend request schema must accept the additive `readiness` field. Routing consumers can exclude `starting`, `unhealthy`, and `stale` servers while continuing to route to `healthy` and `degraded` servers.

## Scope

Readiness validates local configuration and kernel state. It does not create a synthetic WireGuard peer or prove that a packet traverses the tunnel, forwarding, NAT, upstream network, and return path.
