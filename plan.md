# Vprox readiness plan

## Goal

Let the backend distinguish a process heartbeat from a static-IP server that is actually ready to accept and route new peers. The first version should be cheap, self-contained, and have no dependency on DNS or an external HTTP service.

## Short-term implementation

### Cached local readiness check

Each vprox server runs a read-only check immediately after its HTTPS listener starts and every 30 seconds thereafter. It verifies:

- the HTTPS listener is active;
- the expected WireGuard interface is up, has the configured address, key, and listen port, and can be queried through `wgctrl`;
- the bind interface is up and still owns the configured static IP;
- an IPv4 default route exists through the bind interface;
- IPv4 forwarding is enabled;
- every iptables forwarding, NAT, and MSS rule installed by vprox still exists; and
- the peer address pool has capacity.

The check only reads kernel state. It does not create peers, send traffic, or repair networking.

### Readiness state

Store the latest result in memory as `starting`, `healthy`, `degraded`, `unhealthy`, or `stale`, with a stable reason code and timestamps. Three consecutive failures make a previously healthy server unhealthy; two successful checks recover it. A server is never considered ready before its first successful check.

Detailed system errors stay in local logs. The backend receives only stable, low-cardinality reasons.

### Health endpoints

Add two routes to the existing HTTPS listener:

- `GET /health/live` returns `200` while the listener is serving.
- `GET /health/ready` reads the cached snapshot only. It returns `200` for `healthy` or `degraded`, and `503` for `starting`, `unhealthy`, or `stale`.

Both endpoints are self-reliant: no network request or kernel mutation runs in an HTTP handler.

### Backend heartbeat

Extend `/api/admin/staticip/liveness` with a nested `readiness` object while preserving the existing `ip` and `region` fields. Report each configured bind IP separately and send one terminal report if setup fails before the next periodic heartbeat.

Backend support for the additive field must land before this version is deployed. Initially, store and display readiness without changing routing. After validation, exclude `starting`, `unhealthy`, and `stale` servers, then restore them after the reported recovery threshold.

## Verification and rollout

- Unit-test state transitions, staleness, cached endpoint behavior, rule definitions, peer capacity, and heartbeat serialization.
- Build and test for Linux, then run a staging smoke test on a privileged host.
- Remove the bind address, default route, or an installed iptables rule in staging and confirm the expected readiness reason reaches the backend.
- Roll out in shadow mode before enabling routing exclusion.

## Future work

- Add a server-local synthetic WireGuard peer and packet observation (for example, a short-lived `tc` eBPF hook) to prove packets traverse the tunnel, forwarding, and NAT path. Keep this independent of external service uptime.
- Add optional external probes for upstream reachability and public egress-IP validation.
- Correlate classified client failures across agents to detect failures that cannot be observed from the server host.
