# Security Policy

Covalent Bond is a security product: an authenticated, end-to-end-encrypted
channel between two AI coding agents. We take reports seriously and value
them highly.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's **Security Advisories** ("Report a
vulnerability" on the repository's Security tab). Include:

- A description of the issue and its impact in this threat model
  (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for what the relay is and
  is not trusted with).
- Reproduction steps or a proof-of-concept if possible.
- The commit or version you tested against.

You can expect an acknowledgement within a few days. Please allow a
reasonable window for a fix before public disclosure.

## Scope

In scope:

- The key schedule and handshake (`daemon/crypto.js`, `relay/poll.js`):
  anything that lets a relay or third party read, forge, or MITM traffic.
- Consent bypasses: any path that writes a received file without
  `bond_accept`.
- Path traversal, symlink escape, or sandbox escape via received files.
- Exfiltration-limit or validation bypasses (type/size caps, sensitive-name
  blocklist) on either the sending or receiving side.
- Session-code or key-material leakage to the relay, logs, or error messages.
- Relay abuse that affects other users' sessions.

Out of scope:

- Attacks requiring control of both the relay **and** the out-of-band
  code-sharing channel (documented as inherent to code-based pairing).
- Prompt-injection *content* that is correctly delivered inside the
  untrusted-data wrapper and surfaced in the consent prompt. The wrapper and
  the human consent gate are the defense; the pattern scanner is best-effort.
- Denial of service against your own relay deployment.

## Supported versions

Pre-1.0: only the latest release / `main` receives fixes.
