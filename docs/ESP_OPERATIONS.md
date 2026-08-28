# ESP operations for Mac static-IP IPIP tunnels

Operational notes for the ESP layer on the IPIP outer path. Audience:
whoever is on call when a vprox deploy or the Mac static-IP feature needs
to be rolled back in a hurry.

**ESP is MANDATORY on `/connect-ipip`.** The server rejects plaintext
bodies (`{}`, missing/false `esp`) with HTTP 400 "ESP required" before
touching any state, and the Mac agent hard-fails setup if a vprox answer
carries no ESP material. Plaintext IPIP is NOT a supported fallback state:
there is no production configuration that turns it on. (The only override
is the agent's test-only `BLACKSMITH_STATIC_IP_ALLOW_PLAINTEXT=1` env
hatch for staging/lab debugging; nothing in production sets it.) This is
safe because `/connect-ipip` has never carried production traffic — prod
vproxes 405 it — so there are no deployed plaintext clients to stay
compatible with. The WireGuard `/connect` path is unaffected.

**The emergency brake is stopping static-IP admission, not downgrading to
plaintext.** If ESP breaks fleet-wide, stop admitting new Mac static-IP
jobs (and roll back per the runbook below); do not attempt to run the
fleet plaintext. **Rollout gate:** do not register us-central orgs for
Mac static IP until BOTH the vprox fleet and the Mac agents are deployed
from matching revisions — the feature is dark until both sides are live,
and a half-deployed pair fails setup cleanly (400 or agent refusal)
rather than degrading.

## Emergency rollback runbook

A binary downgrade alone is NOT a rollback. ESP state lives in the kernel,
not in the process: SAs and require-ESP policies survive a vprox restart by
design (`RestoreIpipFromKernel` leaves xfrm alone), and the Mac minis hold
the matching state in their own kernels. A downgraded binary that no longer
understands ESP leaves those require-ESP policies in place, and every
plaintext IPIP packet matching them is dropped — the tunnel blackholes
instead of downgrading.

Rolling back therefore means, in this order:

1. **vprox box** — downgrade the binary. The deploy playbook
   (`setup_vprox_server.yaml`) preserves the previously running binary as
   `~/vprox.bak-<date>` in the service user's home directory (next to the
   `~/vprox` checkout it replaces) before each rebuild; copy it back over
   `~/vprox/vprox` and `systemctl restart vprox`. Then flush the kernel
   ESP state:

   ```
   ip xfrm state flush
   ip xfrm policy flush
   ```

   These flush *all* xfrm state on the box. vprox's WireGuard path does not
   use xfrm, so on a vprox gateway this is safe; every ESP'd IPIP pair on
   the box is affected regardless (that is the point of the rollback).

2. **Each affected Mac mini** — flush the SAD and SPD:

   ```
   setkey -F    # flush SAs
   setkey -FP   # flush policies
   ```

   Without this, the mini keeps encrypting outbound (vprox can no longer
   decrypt) and keeps requiring ESP inbound (plaintext from vprox is
   dropped). The agent's next fresh setup re-creates everything it needs;
   flushing is always safe on a mini whose tunnels are being rolled back.

3. The minis' cached gif tunnels will fail their next health check /
   rekey tick and be rebuilt through the normal setup path (or seppuku +
   fresh setup). No manual gif surgery is required, but
   `ifconfig gifN destroy` per leftover gif accelerates recovery.

### How far back can the binary go?

* Rolling back the server to a pre-ESP but IPIP-aware build does NOT
  keep existing tunnels flowing on its own: live pairs hold require-ESP
  kernel policies on BOTH sides, and a downgraded server that answers
  `{"esp": true}` without ESP material leaves those policies dropping
  every plaintext IPIP packet. The flush steps above unblackhole the
  kernels, but fresh setups still FAIL: current agents refuse a tunnel
  without ESP material (ESP is mandatory, fail-closed). A pre-ESP server
  is therefore not a working configuration — treat that rollback as
  "static IP is down until roll-forward" and stop static-IP admission
  for the duration.
* Rolling back to pre-PR-18 main removes `/connect-ipip` entirely. Mac
  static IP is all-or-nothing on that endpoint: every Mac static-IP job
  in the fleet fails until the roll-forward. The blast radius is the
  same as the pre-ESP rollback above (static IP down), so preferring one
  over the other is about the bug you are escaping, not about keeping
  tunnels alive.
* **Cross-boundary skew within the rekey protocol is NOT supported.**
  Earlier drafts of the rekey protocol (the switch-by-timeout build, and
  the first forward-only draft without provisional activation) are NOT
  wire-compatible with the current one, despite sharing the
  PREPARE/ACTIVATE/ABANDON verbs: their failure-handling contracts differ
  (no activation auto-revert, different switch semantics), and a mixed
  pair can diverge kernel state in ways that only a mature tunnel
  reveals. The ONLY skew that works is a pre-rekey ESP agent against a
  new server (fresh connects succeed; such agents never send rekey
  mutations). A genuinely pre-ESP agent fails setup cleanly with the
  mandatory-ESP 400 and mutates nothing. Everything else must be
  deployed from matching revisions -- which the version gate (next
  section) enforces mechanically.

## Rekey protocol version gate

Every rekey MUTATION (`{"esp":true,"rekey":true}` PREPARE, ACTIVATE,
ABANDON) must carry `"espRekeyV": 2`. The server rejects versionless or
mismatched mutations with HTTP 400 and a message naming both versions,
BEFORE touching any state. Fresh connects (`{"esp":true}` without
`rekey`) are exempt. Plaintext bodies never reach the version gate: the
mandatory-ESP check 400s them first ("ESP required"), so a genuinely
pre-ESP agent against a new server fails setup cleanly — that skew is
"supported" only in the sense that it fails fast and mutates nothing.

Operationally: after a partial deploy (old agent + new server or vice
versa), rekey ticks fail fast with the 400 instead of half-running a
protocol the two sides disagree on; the agents' strike machinery tears
the affected tunnels down and rebuilds them once versions match. If the
version-gate 400s show up in the vprox journal, finish the deploy on
whichever side is behind.

## Provisional activation (auto-revert)

An ACTIVATE only provisionally flips the pair's outbound policy. If no
packet arrives on the newly activated generation's inbound SA before the
activation gate expires (~2 minutes; the happy-path client transmits on
the new generation within seconds), the server flips the policy BACK to
the previous generation's reqid on its own and logs loudly
(`esp AUTO-REVERT`). This makes a LOST client ABANDON harmless: a client
whose proof failed keeps transmitting on its old generation, and the
server stops emitting on the unproven one without any message arriving.
Auto-revert and ABANDON are mutually idempotent (epoch- and
reqid-guarded), so duplicates in either order are no-ops. Nothing is
deleted by either path; unproven generations are swept by the next
successful rotation's GC.

## Mac agent rollout gates (staging-verified prerequisites)

* The Mac agent refuses plaintext static-IP tunnels BY DEFAULT — ESP
  mandatory is the shipped behavior, and there is no flag to enable it
  (fail-closed needs no configuration). The only related env var is the
  test-only `BLACKSMITH_STATIC_IP_ALLOW_PLAINTEXT=1` escape hatch, which
  weakens the default for staging/lab debugging; it must never be set in
  any Doppler config (`gha-agent` `stg` or `prd`).
* Rekey alerting lives in the FA repo
  (`agent/grafana/alerts/infrastructure/vm-agent.yaml`): rekey-overdue
  warning at 2h / page at 3h on
  `blacksmith_vm_static_ip_rekey_last_success_age_seconds`, plus
  immediate alerts on `blacksmith_vm_static_ip_rekey_failed` and
  `blacksmith_vm_static_ip_rekey_seppuku`. Deploying those rules is a
  prerequisite for enabling hourly rekey in production.

## Accepted threat model

The ESP keys are minted by vprox and delivered to the Mac helper inside the
`/connect-ipip` HTTPS response. That TLS channel uses vprox's embedded
self-signed certificate and the client dials with certificate verification
disabled (`InsecureSkipVerify`), authenticating itself with the shared
bearer password. Consequences, accepted deliberately:

* **Protected:** passive observation of the LAN/data-center path. All
  tunnel payload is AES-CBC + HMAC-SHA256 ESP; an observer sees only
  ESP frames, and the key material rides inside TLS.
* **Accepted risk:** an active man-in-the-middle on the same LAN at
  handshake time can terminate the skip-verify TLS connection, capture the
  bearer password, and mint/relay keys — i.e. read or alter tunnel traffic
  for sessions it intercepted from the start. This is the exact bootstrap
  trust model of the existing WireGuard `/connect` path (same skip-verify
  TLS, same bearer password), so ESP adds protection without weakening
  anything that exists today.
* **Future fix if scope changes:** pin the embedded vprox certificate in
  the Mac agent (the cert ships in the vprox binary already; the agent
  would verify the presented leaf against the pinned one instead of
  skipping verification). Worth doing before extending static IP beyond
  same-datacenter LANs.

Related invariants the code maintains (do not regress):

* Key material never appears in argv, logs, or error strings (helpers read
  secrets from stdin JSON; outputs are hex-redacted).
* SA generations are FORWARD-ONLY: no SA is ever deleted and re-added.
  Re-adding an outbound SA resets its sequence counter while the peer's
  inbound anti-replay high-water mark survives, so on a mature tunnel
  every packet of the re-added generation is dropped as a replay. The
  rekey protocol therefore proves the new generation carries traffic on
  the wire (PREPARE -> client inbound install -> ACTIVATE policy flip ->
  counter-verified proof) before the client abandons its old outbound
  path, and each side retires old state only on kernel-counter evidence.
  A failed rotation retries forward with a fresh generation, never by
  resurrecting an old one.
* Restart adoption (`RestoreIpipFromKernel`) never touches the xfrm state
  of adopted pairs — including when it deletes a rejected leftover iface
  that shares its remote with an adopted tunnel.
