# Rotate vprox control-server and relay passwords

This runbook covers `vprox server` (HTTPS/WireGuard control plane) and
`vprox relay` (TLS/yamux egress). Rotate both surfaces wherever a relay is
enabled. They are separate processes and restarting one does not reload the
other's credentials.

Complete staging before repeating for production. Runner hosts must be rolled
to load the new client password; keep both passwords accepted until outgoing
agents and their jobs have finished.

## Password semantics and the four phases

| Phase | Server/relay `VPROX_PASSWORD` | Server/relay `VPROX_PASSWORDS` | Client `VPROX_PASSWORD` |
|---|---|---|---|
| Before | old | unset | old |
| Add overlap | old | new | old |
| Move clients and drain | old | new | new for restarted clients; old jobs may remain |
| Retire old | new | unset | new |

Servers and relays accept the **union** of both variables. The singular value
is one literal password; commas in it do not create a list. The plural value
is comma-separated, trims surrounding spaces, and rejects empty entries. A
client still uses one password. Both server/relay values are loaded at startup.

An alternative server-only configuration is plural `new,old` with singular
unset. Whatever representation is used, removing old requires removing it from
**both** variables. Deleting the plural overlap variable while singular still
equals old removes the new password instead.

The HTTP server uses a set of accepted bearer tokens. The relay's authentication
uses channel-bound password proofs; an HTTP result does not validate the relay
handshake. See [relay protocol and lifecycle](RELAY.md).

## 1. Establish coverage, management access, and recovery

1. Start in staging. Record operator, environment, approved target source SHA,
   current/target executable hashes, and rollback location. Fetch current
   `origin/main` and read current instructions before building or deploying.
2. Ensure the approved binary contains multiple-password support for **both**
   commands (PR #24). Build/test in the normal build environment and record the
   output SHA256. Prepare the binary before touching a running service.
3. Build a coverage ledger from deployment inventory, fleet registry, and
   actual serving endpoints. Include gateways whose role/group was misclassified,
   public endpoints whose tailnet reporting is stale, and every enabled relay.
   Inventory name, SSH address, public bind address, and relay address can differ.
4. Verify the current process, binary, bind IP, default route, unit health, and
   credential source. Units may run through a Doppler wrapper; its PID is not
   necessarily the `vprox` process. Inspect units privately because they can
   contain a service token. Do not dump their environment into logs.
5. Back up the working binary and private configuration/source values with
   restrictive permissions. Record ownership/mode, unit command, bind/network
   settings, relay limits, and firewall allowlists. Keep a recovery session open.

For Blacksmith deployments, fa owns `infra/ansible/setup_vprox_server.yaml` and
`infra/ansible/vprox_server_{staging,production}.ini`. The registry role is
`staticip`. That setup playbook performs broad network/provisioning work and
restarts enabled relays; do not run it across the fleet merely to refresh a
password. Use a reviewed canary and one-gateway-at-a-time scope.

### Unreachable SSH is not proof that a gateway is unused

Try the registered management/public address, Tailscale address, and approved
bastion before escalating to the provider console/iDRAC:

```bash
ssh -J '<bastion-user>@<bastion-address>' '<server-user>@<management-address>'
```

If the control endpoint is serving but no management path works, hold client
cutover. Reconcile customer assignment using an approved **dedicated read-only**
identity and check data freshness. Do not use the application's runtime database
credentials or change database/role defaults for an ad hoc query.

An operator may explicitly exclude an unused gateway only after confirming
assignment/routing, preventing new use, updating the registry lifecycle, adding
an explanatory inventory comment, and recording its return-to-service owner.
A comment or an empty customer query alone does not prevent traffic. A returning
gateway must receive current credentials before it is eligible again. Newly
discovered active gateways must join the rotation before clients move.

### Check bind-address lifetime before restarting

On each gateway, inspect:

```bash
ip -j -4 addr show
ip -4 route show default
sudo systemctl is-active vprox
sudo systemctl is-active vprox-relay  # absent/inactive can be valid; record it
```

Some deployed builds refreshed a short-lived bind address. A long stop could
expire it and flush the default route, stranding SSH and preventing startup.
Confirm that the intended bind address is persistently configured and has the
appropriate lifetime before stopping that process. If it is on a finite lease,
stop this rotation step and arrange a reviewed network repair with console
access. Do not invent a replacement address/netmask/route during rotation.
Build/download first and keep the service interruption short.

## 2. Prepare the new password in the actual server secret source

Run the examples in Bash. Create a private working directory, and reuse it for
retries so the replacement key stays the same:

```bash
set +x
umask 077
ROTATION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/credential-rotation.XXXXXX")
export ROTATION_DIR
```

Generate an independent cryptographically random new password. Save it as
`$ROTATION_DIR/vprox.new` and preserve the current password as `$ROTATION_DIR/vprox.old`.
Compare old with all participating client and server sources without printing values.

Save only the raw credential values in `vprox.old` and `vprox.new` inside
that directory, with mode `0600`. Keep these files out of Git and terminal logs.

In Blacksmith the server units use Doppler project `vprox-server`. Determine
the config referenced by the **deployed unit's service token**; do not assume
the config named `prd` is the active one. The production rotation encountered
units using `prd_vprox`; staging used `stg`. Record and verify the actual mapping
for each gateway and relay. Updating an unused config changes no serving process.

For the singular-old/plural-new representation:

1. Privately read back `VPROX_PASSWORD` and confirm it matches old.
2. Inspect `VPROX_PASSWORDS`. If it contains unrelated keys or an unfinished
   prior rotation, preserve the complete accepted set and resolve ownership;
   do not overwrite it with this example.
3. Set only `VPROX_PASSWORDS` to new. Keep singular old and runner values old.

For a verified config where plural was absent, this command uses stdin:

```bash
set +x
export VPROX_SERVER_CONFIG='<verified-server-config>'
doppler secrets set VPROX_PASSWORDS -p vprox-server -c "$VPROX_SERVER_CONFIG" \
  < "$ROTATION_DIR/vprox.new" > /dev/null
```

Read it back into a private comparison script and print only match/no-match.
Changing Doppler does not reload existing processes. Updating Ansible service
tokens is not needed when the token already references the correct config.

## 3. Update and verify one control server

Install the approved multi-password binary if needed, preserving the working
binary and unit settings. Verify the uploaded checksum before installation;
replace via a new inode/atomic rename rather than overwriting the running
executable. Confirm the installed hash and ownership/mode. If the binary already
supports overlap, this is only a credential reload.

```bash
# On the one reviewed gateway, after the preceding checks and backup.
sudo systemctl restart vprox
sudo systemctl is-active vprox
ip -4 route show default
```

Confirm the bind address is still present and the root HTTPS endpoint answers.
Existing WireGuard data-plane interfaces/tunnels normally remain across a
control-server restart; that does not prove a future reconnect will authenticate.
Use the authenticated `/connect` probe below. Do not flap interfaces or reboot
the gateway to validate a password change.

### Non-destructive control-server probe

`POST /connect` authenticates before parsing the peer key. Sending `{}` gives
400 for an accepted password and 401 for a rejected one, without allocating a
WireGuard peer. `GET /` is only a liveness probe.

Save this as `connect-auth-probe.py` in the private operator journal and copy
the script (no keys) to a private temporary directory on the gateway. Run it
**on that gateway over authenticated SSH**, targeting its own bind address.
The local diagnostic uses the service's existing self-signed TLS behavior; do
not reuse it to send bearer passwords to an arbitrary remote unverified server.

```python
import json, ssl, sys, urllib.error, urllib.request
d = json.load(sys.stdin)
ctx = ssl._create_unverified_context()
for case in d['cases']:
    request = urllib.request.Request('https://'+d['bind_ip']+'/connect',
        method='POST', data=b'{}', headers={'Authorization': 'Bearer '+case['key']})
    try:
        with urllib.request.urlopen(request, context=ctx, timeout=10) as response:
            code = response.status
    except urllib.error.HTTPError as error:
        code = error.code
    expected = 400 if case['accept'] else 401
    print(case['label'], code, 'PASS' if code == expected else 'FAIL')
    if code != expected:
        raise SystemExit('Unexpected control-server auth result')
```

Transport the JSON over SSH stdin, not in shell arguments. Example after
installing the script at the reviewed remote path:

```bash
export VPROX_BIND_IP='<gateway-bind-ip>'
export PROBE_PHASE=overlap  # retired only after the retirement gate
python3 - <<'PY' | ssh '<user>@<gateway-management-address>' \
  'python3 /tmp/rotation-probe/connect-auth-probe.py'
import json, os
from pathlib import Path
w = Path(os.environ['ROTATION_DIR'])
phase = os.environ['PROBE_PHASE']; assert phase in ['overlap', 'retired']
print(json.dumps({'bind_ip': os.environ['VPROX_BIND_IP'], 'cases': [
 {'label': 'new', 'key': (w/'vprox.new').read_text().strip(), 'accept': True},
 {'label': 'old', 'key': (w/'vprox.old').read_text().strip(), 'accept': phase == 'overlap'},
 {'label': 'invalid', 'key': 'invalid-credential-rotation-probe', 'accept': False}]}))
PY
```

All three results must match. A timeout/TLS failure is not a password rejection;
investigate routing/listener/bind state. Keep client passwords unchanged while
any eligible gateway remains unverified.

## 4. Reload and probe each enabled relay separately

On gateways with a relay, inspect the loopback metrics:

```bash
curl --fail --silent --show-error http://127.0.0.1:9444/metrics \
  | grep -E '^vprox_relay_(sessions_open|streams_open|draining)'
```

The relay's SIGTERM closes its listener, sends GoAway, and allows open streams
only `--drain-timeout` before cutting them. The systemd stop timeout must exceed
that grace. A restart is not automatically transparent to active Mac jobs.
Prefer waiting for zero active sessions during this rotation, or use an
explicitly approved workload-drain/maintenance plan. Recheck immediately before
the restart; a quiet sample is not a guarantee that no new session can arrive.
Coordinate allocation/drain when uninterrupted existing sessions are required.

```bash
# Only when the reviewed relay drain conditions are satisfied.
sudo systemctl restart vprox-relay
sudo systemctl is-active vprox-relay
curl --fail --silent --show-error http://127.0.0.1:9444/metrics
```

Then perform the protocol handshake with new, old, and invalid passwords from
an **allowed source CIDR**. A loopback probe can fail the source allowlist before
auth. Do not weaken the firewall or `--allow-source` just to run a probe. Use an
approved runner/source, with the target static IP actually assigned to the relay.

The following verifies both the hello status and the server's channel-bound
proof, then closes without opening any destination streams. Save it as
`$ROTATION_DIR/relay-auth-probe.go` and build from this repository's approved
checkout in the normal build environment:

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/modal-labs/vprox/lib/relayproto"
)

type probeCase struct {
	Label, KeyFile string
	Accept         bool
}
type input struct {
	Address, StaticIP string
	Cases             []probeCase
}

func check(in input, c probeCase) error {
	raw, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return fmt.Errorf("empty key")
	}
	// The protocol authenticates the relay with a TLS-exporter-bound proof.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second},
		"tcp", in.Address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		return fmt.Errorf("relay dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	binding, err := relayproto.ChannelBinding(conn.ConnectionState())
	if err != nil {
		return err
	}
	if err := relayproto.WriteHello(conn, relayproto.HelloBody{
		Auth: relayproto.ClientProof(key, binding), VMID: "credential-rotation-probe",
		StaticIP: in.StaticIP,
	}); err != nil {
		return err
	}
	result, reply, err := relayproto.ReadHelloReply(conn)
	if err != nil {
		return err
	}
	pass := result == relayproto.HelloUnauthorized
	if c.Accept {
		pass = result == relayproto.HelloOK &&
			relayproto.VerifyProof(reply.Proof, relayproto.ServerProof(key, binding))
	}
	fmt.Printf("%s %s pass=%t\n", c.Label, relayproto.HelloStatusString(result), pass)
	if !pass {
		return fmt.Errorf("unexpected relay auth result for %s", c.Label)
	}
	return nil
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "invalid probe description")
		os.Exit(1)
	}
	for _, c := range in.Cases {
		if err := check(in, c); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
```

```bash
go build -o "$ROTATION_DIR/relay-auth-probe" "$ROTATION_DIR/relay-auth-probe.go"
export RELAY_ADDRESS='<relay-ip>:9443'
export RELAY_STATIC_IP='<static-egress-ip-on-relay>'
export PROBE_PHASE=overlap
python3 - <<'PY' | "$ROTATION_DIR/relay-auth-probe"
import json, os
from pathlib import Path
w = Path(os.environ['ROTATION_DIR'])
phase = os.environ['PROBE_PHASE']; assert phase in ['overlap', 'retired']
(w/'vprox.invalid').write_text('invalid-credential-rotation-probe')
print(json.dumps({'Address': os.environ['RELAY_ADDRESS'],
 'StaticIP': os.environ['RELAY_STATIC_IP'],
 'Cases': [{'Label': label, 'KeyFile': str(w/('vprox.'+label)), 'Accept': accept}
           for label, accept in [('new', True), ('old', phase == 'overlap'), ('invalid', False)]]}))
PY
```

Run the executable and its private key files on the allowed source. A TCP/TLS
handshake alone is insufficient. New and old must receive `ok` with a verified
server proof during overlap; invalid must receive `unauthorized`.
`bad_static_ip`, `session_limit`, source rejection, and timeout need separate
diagnosis and are not auth passes. Record HTTP and relay results independently.

## 5. Complete server coverage, then move clients

After the canary passes, repeat one gateway/relay at a time. Refresh the union
of inventory, registry, and actual serving endpoints before declaring coverage.
Each ledger row needs new/old/invalid control results and, where applicable,
relay results plus executable hash and secret-source identity.

Only then change every participating runner `VPROX_PASSWORD` to the **single**
new password in all applicable Doppler `gha-agent` configs for the selected
environment. Include regional configs, Linux ARM, and both Mac regions. Read
back each write without printing secrets. Do not create missing variables
without reviewing why they were absent.

It is valid to stop here if the requested scope is server overlap and Doppler
only. Keep old accepted until the later client roll/drain. When authorized,
gracefully roll all live/reporting runner hosts. Inspect actual process
credentials, old jobs, and host egress-proxy consumers. An existing WireGuard
tunnel or relay session can keep working while its next reconnect would still
use the old password.
Do not treat today's successful egress as proof that old is unused.

## 6. Retire old, including both variables and both processes

After all old-key clients/jobs have drained and offline consumers have an
enforced return-to-service plan:

1. Set singular server `VPROX_PASSWORD` to new and verify it by private readback.
2. Remove temporary `VPROX_PASSWORDS` only after singular is confirmed new.
   If unrelated passwords are intentionally retained, remove only the retired
   member and preserve the rest instead of deleting the variable.
3. Restart/probe the control server, then restart/probe an enabled relay under
   the same session-drain rules. Repeat for every eligible gateway.

For the simple two-key Doppler case:

```bash
doppler secrets set VPROX_PASSWORD -p vprox-server -c "$VPROX_SERVER_CONFIG" \
  < "$ROTATION_DIR/vprox.new" > /dev/null
# STOP and privately read back singular = new before the next command.
doppler secrets delete VPROX_PASSWORDS -p vprox-server -c "$VPROX_SERVER_CONFIG" --yes
```

Run both probes with `PROBE_PHASE=retired`: new remains accepted; old and invalid
must be rejected. Verify a real WireGuard reconnect and a Mac static-IP egress
canary using an operator-owned workload. Do not disturb a customer job's tunnel
for the test. Observe `vprox_relay_hello_refused_total{status="unauthorized"}`,
source rejections, sessions, stream health, and reconnect logs; account for
deliberate negative probes.

Record final coverage and any gateway that must stay excluded. Remove transient
probe files/uploads and protected recovery material according to retention
policy. Credential retirement prevents future authentication; it does not
terminate every already-established WireGuard tunnel. Emergency containment of
a compromised active tunnel is a separate operation.

## Recovery

Before clients change, restore the backed-up binary/source and prove old works.
Once any client uses new, restore **overlap** during recovery. Reverting to an
old binary that ignores `VPROX_PASSWORDS` will break new-password clients.

If the new key fails after a Doppler update, check the actual token-to-config
mapping, process start time, binary support, and both variables. If HTTP passes
but relay fails, check the relay's independent process/config, source allowlist,
requested static IP, and server-proof validation. Do not broaden network policy
or bypass proof verification to force a pass.

If a restart loses the bind address/default route, stop fleet expansion and use
the prepared console/network recovery path. If old clients remain after the
agent roll, preserve overlap and inspect jobs by PID; do not kill their jobs to
finish the rotation. Report “server updated,” “client configured,” “agent
handover,” “old jobs drained,” and “old rejected” separately.
