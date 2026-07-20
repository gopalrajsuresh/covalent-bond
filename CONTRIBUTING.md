# Contributing to Covalent Bond

Thanks for your interest in improving Covalent Bond. This project is small on
purpose (a tight, auditable security surface is a feature), so contributions
are judged first on whether they keep that property.

## Before you start

1. Read the **security invariants** below. A PR that violates one will be
   closed regardless of how useful the feature is.
2. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the protocol,
   threat model, and where each piece of code lives.
3. Check open issues before filing a new one or starting significant work.

## Security invariants: never break these

- **No stdout writes** from any module the MCP server loads (`daemon/`,
  `mcp/`, `relay/`, `security/`, `transfer/`): stdout is the MCP JSON-RPC
  stream. Log to stderr via the shared `logger` in `security/index.js`.
- **The session code never leaves the machine to the relay.** The relay is
  addressed only by the routing ID (`PBKDF2(sessionCode)`). The code is the
  secret that defeats a malicious relay.
- **No received file is written to disk without explicit `bond_accept`**
  (human consent). Incoming transfers stay pending until then.
- **All peer content is untrusted data.** Keep the untrusted-content wrapper;
  never let received text be interpreted as instructions.
- **The session key is derived once per session** (never the 600k-iteration
  PBKDF2 per message), and ephemeral private keys are wiped once it exists.
- **Local servers bind to `127.0.0.1`**, never `0.0.0.0`.
- **Crypto domain constants stay stable** (`CovalentBond-Routing`,
  `CovalentBond-CodeKey`, `CovalentBond-SessionKey`, `CovalentBond-Confirm`).
- **No weakening of validation** (file-type whitelist, size caps, path
  safety, code/routing-ID formats) to make a feature or test work.
- **No new runtime dependencies** without a clearly argued need, and no
  telemetry or network calls to anything but the configured relay.

## Development setup

```bash
git clone https://github.com/gopalrajsuresh/covalent-bond.git covalent-bond
cd covalent-bond
npm install
npm test          # every suite must pass; runs against an in-process mock relay
```

No network, no Cloudflare account, and no secrets are needed to develop or
test. `npm run relay:dev` starts a local relay on `http://localhost:8787` for
manual runs.

## Branching and merge flow

`main` is the release branch and is **maintainer-merged only**: no direct
pushes, no PRs targeting `main`.

1. Branch off **`dev`**, named by intent:
   `feature/<short-name>`, `fix/<short-name>`, `chore/<short-name>`,
   `docs/<short-name>`, or `test/<short-name>`.
2. Open your PR **against `dev`**. CI (the full test suite) must be green.
3. After review and merge into `dev`, the maintainer batches verified changes
   from `dev` into `main`. Only `main` is ever released or deployed from.

Keep branches focused: one logical change per branch/PR. Rebase on `dev`
rather than merging `dev` into your branch when you need to catch up.

## Making changes

- **Smallest edit that does the job, in the right module** (see the layout
  in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- **Every bug fix or new behavior ships with a test** in `test/*.test.js`.
  The runner picks up any `*.test.js` file automatically.
- **`npm test` must be green before every commit**, including the `mitm`
  suite; it is the guardrail for the security model.
- Match the surrounding code's style and comment density. Comments explain
  constraints the code can't show.

## Commits and pull requests

- **Commit message: exactly one line**, present tense, specific
  (`reject all-zero X25519 public keys during key agreement`). Detail goes in
  the PR description, not the commit.
- **PR title:** a plain statement of the change.
- **PR description:** what changed, why it matters, and how it was validated
  (which tests).
- One logical change per PR.

## Security-sensitive changes

If a change touches the key schedule, the wire protocol, the consent flow, or
any invariant above, say so explicitly in the PR description and explain why
it is safe. For reporting vulnerabilities, see [SECURITY.md](SECURITY.md);
do not open a public issue.

## Releases and deploys

`npm publish` and relay deploys are maintainer-only and owner-gated. PRs never
include them.
