# Vprox readiness checks

Vprox reports the routing health of each configured bind IP through its periodic backend heartbeat. The heartbeat also shows that the process is reporting.

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

When a server becomes unhealthy, vprox logs the stable failure reason locally. Readiness check failures also include the detailed system error in local logs. Failure reasons and system errors are not included in heartbeat payloads.

## Backend heartbeat

The existing `/api/admin/staticip/liveness` heartbeat contains `ip`, `region`, and a `healthy` boolean for each configured bind IP. Heartbeats continue while a running server is degraded or unhealthy. If setup or the listener fails before the next periodic heartbeat, vprox sends `healthy: false` once before exiting.

`healthy` represents routing eligibility. It is true for the internal `healthy` and `degraded` states and false for `starting`, `unhealthy`, and `stale`. The detailed cached readiness state remains local to vprox.

Vprox does not expose separate liveness or readiness endpoints. Health state is pushed to the backend through this heartbeat.

## Scope

Readiness validates local configuration and kernel state. It does not create a synthetic WireGuard peer or prove that a packet traverses the tunnel, forwarding, NAT, upstream network, and return path.
