# Covalent Bond Relay - Cloudflare Worker + Durable Objects

The relay is a "dumb pipe": one Durable Object per routing ID holds the
session's public keys and encrypted message queue, strongly consistent and
single-threaded (no races, no eventual-consistency lag). All state is
deleted by an alarm 30 minutes after the last activity. The relay never
sees the session code, private keys, or any plaintext.

## Setup

### 1. Install Wrangler (Cloudflare CLI)

```bash
npm install -g wrangler
```

### 2. Login to Cloudflare

```bash
wrangler login
```

### 3. Deploy

No KV namespaces and no secrets are required: session state lives in the
Durable Object declared in `wrangler.toml` (the `v1-session-do` migration
runs automatically on first deploy).

```bash
cd cloudflare-worker
wrangler deploy
```

You'll get a URL like: `https://covalent-bond-relay.YOUR_SUBDOMAIN.workers.dev`

### Optional: per-IP throttle

Per-session rate limiting is always enforced inside the Durable Object.
To additionally throttle by client IP, uncomment the `IP_LIMITER`
rate-limiting binding in `wrangler.toml`. The worker detects the binding at
runtime; without it, per-IP throttling is simply skipped.

## Testing locally

For local development you don't need `wrangler`: `npm run relay:dev` (from
the `covalent-bond` folder) starts an in-process mock relay with the same API on
`http://localhost:8787`. To run the real Worker locally instead: `wrangler dev`.

## Protocol note

The relay is addressed by a **routing ID** (`PBKDF2(sessionCode)`, 64 hex
chars), never by the session code itself. The relay stores only public keys
and ciphertext, and **cannot** derive the session key; that also requires
the session code, which never reaches the relay. See
[../README.md](../README.md).

Messages carry a relay-assigned, per-session **sequence number**; clients
poll with `since=<last seq>`, so delivery never depends on timestamps.

## API Endpoints

### `POST /create`
Create a new session. Re-creating a routing ID with a live session is
refused (403), so an attacker who learns a routing ID cannot clobber it.

**Request:**
```json
{
  "routingId": "64-hex-char-routing-id",
  "publicKey": "hex-x25519-public-key",
  "peerId": "peer-abc123"
}
```

**Response:**
```json
{ "ok": true, "routingId": "…", "expiresAt": 1234567890 }
```

### `POST /join`
Join an existing session. Registers the joiner's public key and returns the host's.

**Request:**
```json
{
  "routingId": "…",
  "publicKey": "hex-x25519-public-key",
  "peerId": "peer-xyz789"
}
```

**Response:**
```json
{ "ok": true, "hostPublicKey": "…", "peerCount": 2 }
```

### `POST /send`
Queue an encrypted payload for the other peer.

**Request:**
```json
{
  "routingId": "…",
  "fromPeerId": "peer-abc123",
  "encryptedPayload": { "v": 2, "iv": "…", "encrypted": "…", "authTag": "…" }
}
```

### `GET /poll`
Poll for new messages.

**Query params:** `routingId`, `peerId`, `since` (last seen sequence number).

**Response:**
```json
{
  "messages": [
    { "from": "peer-xyz789", "seq": 3, "payload": { "v": 2, "iv": "…", "encrypted": "…", "authTag": "…" }, "timestamp": 1234567890 }
  ],
  "disconnected": false
}
```

System messages (`peer_joined`, `disconnect`) are delivered on this channel with `from: "system"`.

### `POST /disconnect`

**Request:** `{ "routingId": "…", "peerId": "peer-abc123" }`

## Security properties

- **Sees only ciphertext + public keys**: never plaintext, never the session code
- **Cannot derive the session key**: that requires the out-of-band session code
- **Routes by routing ID**: `PBKDF2(code)`, not the code itself
- **Max 2 peers per session**; a live routing ID cannot be re-created
- **Atomic state**: one Durable Object per session; no lost messages
- **Sequence-numbered delivery**: no timestamp-cursor races
- **Payload caps enforced on actual bytes received**, not headers
- **Per-session rate limiting** (10 msg/min per peer) inside the object
- **Auto-expiry**: alarm deletes all state 30 min after last activity
- **Message queue capped** at 100 per session
- **No CORS**: the relay serves native clients, not browsers
- No secrets to configure; nothing to misconfigure into a default credential

## Free-tier estimate

With 5-second polling, one active session (two peers) makes ~1,440
requests/hour, and each Worker request invokes the session's Durable Object.
The Workers free tier (100k requests/day, plus Durable Object request and
duration allowances) comfortably covers a handful of concurrent sessions or
~100 half-hour sessions per day. For heavier use, the $5/month paid tier
removes any practical limit for this workload.

## Production Setup

For production, use a custom domain instead of `*.workers.dev`:

1. Add domain to Cloudflare
2. Uncomment `routes` in `wrangler.toml`
3. Set `pattern = "relay.yourdomain.com"`
4. Deploy

This prevents corporate firewall blocking of `*.workers.dev` domains.
