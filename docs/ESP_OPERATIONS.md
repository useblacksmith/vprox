# ESP operations for Mac static-IP IPIP tunnels

Operational notes for the ESP layer on the IPIP outer path. Audience:
whoever is on call when a vprox deploy or the Mac static-IP feature needs
attention in a hurry.

**ESP is MANDATORY on `/connect-ipip`, and the wire protocol is versioned.**
Every request must be `{"version":1,"op":...}` with op one of
`connect | prepare | activate`; anything else — including the empty body,
`{}`, and every legacy `{"esp":...}` shape — is rejected with HTTP 400
BEFORE any peer lookup or mutation. There is no plaintext IPIP, no request
flag to ask for it, and no environment override on the agent (the old
test-only `BLACKSMITH_STATIC_IP_ALLOW_PLAINTEXT` hatch is gone; tests use
an in-process seam). This is safe because `/connect-ipip` has never
carried production traffic — prod vproxes 405 it — so there are no
deployed clients to stay compatible with. The WireGuard `/connect` path is
unaffected.

## The forward-only rotation contract (no rollback)

The SAs have no lifetimes and no ESN (macOS setkey cannot install ESN), so
a non-ESN SA hard-stops at sequence 2^32; the Mac agent's tunnel actor
rotates SA generations hourly. Generations move FORWARD ONLY — no SA is
ever deleted and re-added (a re-added outbound resets its sequence counter
while the peer's anti-replay high-water mark survives: instant permanent
blackhole on a mature tunnel), and there is **no abandon, no revert, no
rollback of any kind**:

```text
stable N → prepared N+1 → activated N+1 → proven → switched → stable N+1

failure before ACTIVATE           → reap pending, retry at next hourly tick (N untouched)
proof/switch failure INCONCLUSIVE → nothing destructive; re-prove next tick
proof/switch failure DEAD         → exactly ONE forward retry (fresh N+2, in-tick)
retry also DEAD                   → TERMINAL
```

Wire ops:

* `{"version":1,"op":"connect"}` — destructive fresh install (new tunnel).
* `{"version":1,"op":"prepare"}` — mint + install generation N+1 on the
  vprox side without flipping the outbound policy; keys returned over TLS.
* `{"version":1,"op":"activate","target":"<hex>","expectedActive":"<hex>"}`
  — **fenced** compare-and-swap flip of the outbound policy: it succeeds
  only if the policy currently selects `expectedActive`'s generation. A
  delayed/replayed activate for a superseded generation gets HTTP 409, a
  body naming the real active generation, and mutates NOTHING. Activating
  the already-active target is idempotent 200.

Server-side failure handling is ONE housekeeping sweep (every 5 s,
extending the vanished-peer reaper): reap prepared-but-never-activated
generations after ~5 min (`VPROX_ESP_PENDING_DEADLINE`), counter-gated GC
of superseded generations after the client provably transmits on the new
one plus a ~2 min grace (`VPROX_ESP_GC_GRACE`), orphan aging, and
vanished-peer reaping. The sweep never touches the active generation, a
pending within deadline, or anything a transition references, and treats
an unreadable counter as UNKNOWN (skip), never as zero. Sweep health is
log-based: `ipip housekeeping healthy` every ~10 min plus immediate error
lines.

There are no per-rekey goroutines, no epochs, no activation gate, no
auto-revert: the fenced activate plus the sweep replace all of it.

## Restart semantics

`RestoreIpipFromKernel` adopts leftover tunnels and reconstructs each
pair's ACTIVE generation from kernel truth — the outbound policy's
template reqid IS the active generation's SpiToClient. No transition state
is persisted: orphan pending states are swept by the housekeeper after
their deadline, and the client's fenced activate carries its own
`expectedActive`, so a restarted vprox answers it correctly with no
memory. **A restart mid-transition also loses the Mac agent's one-recovery
budget** (it lives on the actor goroutine's stack, deliberately never
persisted), so the next evaluation after a crash-loop may go TERMINAL
instead of retrying — accepted: a tunnel that keeps crashing mid-rotation
should die loudly, not wobble.

## TERMINAL (replaces rollback, strikes, and seppuku)

When a tunnel cannot rotate — a rotation convicted DEAD twice within one
recovery budget, the sequence-headroom audit crossing 2^31
(`BLACKSMITH_STATIC_IP_SEQ_TERMINAL_THRESHOLD` overrides for tests) while
rotation is blocked, headroom staying UNPROVABLE (counter reads failing)
continuously past `BLACKSMITH_STATIC_IP_HEADROOM_UNKNOWN_WINDOW` (default
6 h), or vprox reporting the pair rebuilt (`Fresh`) — the Mac agent runs
the TERMINAL procedure. Every teardown of an entry that still has holder
VMs funnels through the same procedure (including a cached tunnel probed
DEAD and a quarantined entry being retried); raw teardown is only legal
at zero holders.

1. stop admissions on the tunnel entry and drain ATTACHING holders (VMs
   whose setup is still in flight: their setup revalidates the entry
   before committing PF rules and again before VM start, so a fenced
   entry fails their setup with a retryable error and the job requeues);
2. join the tunnel actor (join timeout ⇒ quarantine; nothing is destroyed
   while the owner may still run);
3. install **PF drop guards** for the exact holder set and kill their pf
   states, VERIFYING the drops took effect **before** the gif is
   destroyed. Live holders get TWO copies: one in a TERMINAL-owned anchor
   (`blacksmith-sip/term-<vmid>`) that per-VM cleanup never touches, and
   one replacing the per-VM anchor's rules in place. This is fail-closed
   by construction: the per-VM `route-to` rule is stateful and the
   baseline mac policy broadly allows VM internet, so without guards a
   destroyed gif would let VM traffic egress `en0` under the mini's own
   source IP — an allowlist-contract violation worse than the outage. If
   a guard cannot be verified, the entry is quarantined with the gif
   intact instead.
4. terminate every live holder VM through the VM-stop machinery with the
   distinct `StaticIPTunnelLost{VMID, JobID, VproxIP}` reason (StopVM
   errors are NOT success);
5. CONFIRM each holder VM's death (bounded poll of the VM object's state
   / manager ownership). A holder's terminal-owned guard is removed only
   after THAT holder is confirmed gone; any unconfirmed holder ⇒
   quarantine with all guards intact. The next acquisition resumes the
   procedure idempotently (guards may already exist; re-verify, continue);
6. tear down (gif destroyed + verified absent, IPsec flushed, entry
   removed); the next acquisition builds fresh;
7. emit `blacksmith_vm_static_ip_terminal` (reason + vprox_server_ip) and
   `blacksmith_vm_static_ip_terminal_jobs`.

**Product decision (approved, do not regress): jobs terminated by a
TERMINAL event are NOT automatically rerun.** This is the same contract as
host death. The termination is attributed as infrastructure (never a
customer failure) and the terminal counter pages, so the attribution is
loud; replaying the affected work is a human/product decision, not agent
behavior. Documented in `jobsbase.StaticIPTunnelLost` and the vm-agent
alert rules.

## Observability and the canary plan

Alerting lives in the FA repo
(`agent/grafana/alerts/infrastructure/vm-agent.yaml`):

* rekey-overdue on `blacksmith_vm_static_ip_rekey_last_success_age_seconds`
  — warn at 2 h, page at 3 h (a genuinely failing tunnel goes terminal
  within one tick, so a climbing age means a permanent-INCONCLUSIVE
  environment or a wedged actor);
* `blacksmith_vm_static_ip_rotation_attempts{phase,outcome}` — every
  rotation phase outcome; the `outcome="dead"` delta alerts as the early
  warning;
* `blacksmith_vm_static_ip_terminal` — **page-level**; every terminal
  event pages with its reason and vprox attribution.

These metrics are the CANARY for wide enablement: run the fleet at
staging/limited scope and measure the real-world p(dead)/rotation and
p(terminal)/rotation from `rotation_attempts` and `terminal` before
enabling more orgs. A terminal rate visibly above the vprox-host incident
rate means the proof/switch path is misfiring and enablement must pause.

vprox itself has no prometheus; its sweep health, fence rejections
(`esp activate FENCED`), and reap/GC decisions are structured log lines in
the vprox journal.

## Emergency handling

A binary downgrade alone is NOT a rollback: ESP state lives in the kernel,
not the process (SAs and require-ESP policies survive a vprox restart by
design, and the minis hold matching state). **The emergency brake is
stopping static-IP admission, not downgrading.** If ESP breaks fleet-wide:

1. Stop admitting new Mac static-IP jobs.
2. **vprox box** — if the binary must move, the deploy playbook
   (`setup_vprox_server.yaml`) preserves the previous binary as
   `~/vprox.bak-<date>`; copy it back over `~/vprox/vprox` and
   `systemctl restart vprox`. Then flush kernel ESP state:

   ```
   ip xfrm state flush
   ip xfrm policy flush
   ```

   (Flushes ALL xfrm on the box; vprox's WireGuard path does not use
   xfrm, so on a vprox gateway this is safe.)
3. **Each affected Mac mini** — `setkey -F` (SAs) and `setkey -FP`
   (policies), then let the agents rebuild through the normal setup path.

Cross-revision skew within the rotation protocol is NOT supported: the
explicit `version` on every request rejects a mismatched pair with a 400
before any state is touched, so a half-deployed fleet fails setup cleanly
instead of degrading. Deploy both sides from matching revisions and keep
the feature dark until both are live.

## Accepted threat model

The ESP keys are minted by vprox and delivered to the Mac helper inside
the `/connect-ipip` HTTPS response. That TLS channel uses vprox's embedded
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
  secrets from stdin JSON; outputs are hex-redacted; transition keys live
  only in the actor's memory for the life of one transition).
* SA generations are FORWARD-ONLY, and ambiguity is resolved by READ-ONLY
  inspection of kernel truth (the helper's `report` mode on the Mac, the
  fenced CAS on vprox) followed by a retry of the SAME target — never by
  minting a fresh generation for an existing transition, and never by
  deleting the target "to be safe".
* The housekeeping sweep and the Mac GC step are counter-gated: nothing
  superseded is deleted until the new generation provably carries packets,
  plus a grace period.
* Restart adoption (`RestoreIpipFromKernel`) never touches the xfrm state
  of adopted pairs — including when it deletes a rejected leftover iface
  that shares its remote with an adopted tunnel.
* PF fail-closed before gif destruction: any teardown path where VMs may
  still reference the gif installs and verifies drop guards first (for
  live holders, in a TERMINAL-owned anchor that survives per-VM cleanup),
  and destroys nothing until every holder's death is confirmed.
