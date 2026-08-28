# ESP operations for Mac static-IP IPIP tunnels

Operational notes for the ESP layer on the IPIP outer path (`/connect-ipip`
with `{"esp": true}`). Audience: whoever is on call when a vprox deploy or
the Mac static-IP feature needs to be rolled back in a hurry.

## Emergency rollback runbook

A binary downgrade alone is NOT a rollback. ESP state lives in the kernel,
not in the process: SAs and require-ESP policies survive a vprox restart by
design (`RestoreIpipFromKernel` leaves xfrm alone), and the Mac minis hold
the matching state in their own kernels. A downgraded binary that no longer
understands ESP leaves those require-ESP policies in place, and every
plaintext IPIP packet matching them is dropped — the tunnel blackholes
instead of downgrading.

Rolling back therefore means, in this order:

1. **vprox box** — downgrade the binary (a `vprox.bak-*` copy next to the
   deployed binary, `systemctl restart vprox`), then flush the kernel ESP
   state:

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

* Rolling back to a pre-ESP but IPIP-aware build keeps Mac static IP
  working in plaintext (clients requesting `{"esp": true}` fall back:
  the server ignores the field and answers with the plaintext response
  shape, which the helper handles).
* Rolling back to pre-PR-18 main removes `/connect-ipip` entirely. Mac
  static IP is all-or-nothing on that endpoint: every Mac static-IP job
  in the fleet fails until the roll-forward. Do not do this to fix an
  ESP-only problem; use a plaintext-capable build plus the flushes above.

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
* The rekey path is additive: a new generation is installed alongside the
  old, the switch is confirmed by traffic counters, and rollback keeps the
  previous generation decryptable on both sides.
* Restart adoption (`RestoreIpipFromKernel`) never touches the xfrm state
  of adopted pairs — including when it deletes a rejected leftover iface
  that shares its remote with an adopted tunnel.
