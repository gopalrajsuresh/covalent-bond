# Testing Covalent Bond on Two Machines

End-to-end test of the authenticated E2EE channel between two computers.

## What this tests

- Session creation on Machine 1 (host) and joining from Machine 2 (guest)
- X25519 key agreement over the internet through the untrusted relay
- **Authenticated handshake**: mutual key confirmation using the out-of-band session code
- AES-256-GCM encrypted messaging in both directions
- The Cloudflare Worker relay (or any relay you point at)

## Prerequisites

Both machines need:
1. Node.js v18+
2. A copy of the `covalent-bond` folder (run `npm install` once)
3. Outbound HTTPS to the relay (no inbound ports; works behind NAT)

By default the drivers point at `http://localhost:8787` (the mock relay). To
use a deployed relay, set:
```bash
export COVALENT_RELAY_URL=https://your-relay.workers.dev   # (Windows: $env:COVALENT_RELAY_URL=...)
```

## Run it

### Machine 1: host

```bash
cd covalent-bond
node two-machine/host.js
```

Output includes:
```
📢 SHARE THIS CODE WITH THE OTHER MACHINE (out-of-band):
      AbCd-1234-XyZw
(The relay never sees this code; it is the shared secret.)
```

**Share that code with Machine 2 over a channel the relay operator does NOT control**: chat, voice, in person. Do **not** paste it into the relay. Its secrecy is what protects you against a malicious relay.

### Machine 2: guest

```bash
cd covalent-bond
node two-machine/guest.js AbCd-1234-XyZw     # or run with no arg and paste when prompted
```

### Expected result

Both sides print, in order:
```
🔐 Secure channel established; peer verified ...
💬 <peer> says: "Hello from the ..."
📤 Sent encrypted ... 
✅ TWO-MACHINE E2E TEST SUCCESSFUL
```

If either side prints `🚨 Handshake failed`, the session key confirmation did not match, which is exactly what a key-substituting (MITM) relay, or a mistyped session code, would cause. The session aborts before any data is exchanged.

## Local dry run (no second machine, no network)

You can exercise the same drivers against the in-process mock relay:

```bash
cd covalent-bond
npm run relay:dev        # terminal 1: starts mock relay on :8787
COVALENT_RELAY_URL=http://127.0.0.1:8787 node two-machine/host.js    # terminal 2
COVALENT_RELAY_URL=http://127.0.0.1:8787 node two-machine/guest.js <code>   # terminal 3
```

On Windows (PowerShell), set the variable first instead of prefixing:

```powershell
$env:COVALENT_RELAY_URL = "http://127.0.0.1:8787"
node two-machine/host.js
```

The automated suite (`npm test`) also covers the full handshake and a simulated malicious relay; see `test/handshake.test.js` and `test/mitm.test.js`.

## Testing with the agent (MCP)

With the MCP server configured on both machines:
- Machine 1: "Create a Covalent Bond session" → the agent calls `bond_connect` → share the code out-of-band.
- Machine 2: "Join Covalent Bond session `<code>`" → the agent calls `bond_join`.
- Check `bond_status` on both until it shows **Secure channel established**.
- Machine 1: "Send `<file>` to my peer" → Machine 2 sees a consent prompt → "accept the transfer".

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Session not found` | Host must create the session first; code is case-sensitive; sessions expire after 30 min |
| `Relay health check failed` | Check the relay URL: `curl <relay>/health` should return `{"status":"ok",...}` |
| `Handshake failed` | Code mismatch (retype it), or, if the code is correct, a possible relay MITM. Do not proceed |
| Timeout | Both machines need outbound HTTPS; verify the other side is running |

## What the relay sees, and never sees

**Sees:** the routing ID (`PBKDF2(code)`, not the code), both public keys, AES-256-GCM ciphertext, timestamps.

**Never sees:** the session code, private keys, the derived session key, or any plaintext / file content.

A passive relay learns nothing. An active relay that substitutes keys cannot derive the session key (it lacks the code), so key confirmation fails and the session aborts. This is the property proven by `test/mitm.test.js`.

## Check the audit log

Every operation is recorded at `~/.covalent/audit.log` on each machine (JSON lines).
