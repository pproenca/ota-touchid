# ota-touchid

Over-the-air Touch ID authentication for remote Macs. Approve Touch ID prompts on a Mac with Touch ID and relay the result to a remote Mac over the local network.

Built on Secure Enclave, TLS, and Bonjour. Zero passwords — every authentication is a biometric event signed by hardware.

## Install

```bash
# Homebrew
brew install pproenca/tap/ota-touchid

# or curl (installs to ~/.local)
curl -fsSL https://raw.githubusercontent.com/pproenca/ota-touchid/master/scripts/install.sh | bash
```

### Requirements

- macOS (Apple Silicon)
- Touch ID (server Mac)

## Quick start

On the Mac with Touch ID (server):

```bash
ota-touchid setup
```

This installs the launchd service and prints a one-line pairing token.

On the remote Mac (client):

```bash
ota-touchid pair <pairing-bundle>
ota-touchid test
ota-touchid auth --reason sudo
```

## Commands

| Command | What it does |
|---|---|
| `setup` | Generate keys, install server as launchd agent |
| `pair <pairing-bundle\|psk>` / `pair --stdin` | Import pairing data on client |
| `trust <server-public-key-base64>` | Pin trusted server key on client |
| `auth` | Authenticate via Touch ID (exit 0=ok, 1=denied) |
| `test` | Verify secure connectivity and server authenticity |
| `serve` | Run server in foreground |
| `status` | Show config & service status |
| `uninstall` | Stop service, remove launchd agent |

### Auth options

```
--reason <text>              Reason shown in Touch ID prompt (default: "authentication")
--host <ip-or-hostname>       Direct connection (skip Bonjour discovery)
--port <port>                 Optional with --host (default: 45821)
--allow-tofu                 Explicitly allow trust-on-first-use for this auth attempt
```

## How it works

1. **Server** runs on a Mac with Touch ID. On `setup`, it creates a P256 key pair in the Secure Enclave and a pre-shared key (PSK) for client authentication.

2. **Client** discovers the server via Bonjour (or uses direct/cached endpoint). It sends an authenticated request transcript MAC (HMAC-SHA256 over mode + nonce + reason + hostname + flags).

3. **Server** validates the request MAC. For auth mode, it prompts Touch ID and signs a transcript payload (`nonceC || nonceS || reasonDigest || channelBinding`) using Secure Enclave.

4. **Client** verifies response MAC (PSK + TLS channel binding) and then verifies Secure Enclave signature against pinned server key.

All traffic is TLS-encrypted with channel binding to prevent MITM attacks. The server rate-limits requests and logs every authentication event to `~/.config/ota-touchid/audit.log`.

## Security

- **Secure Enclave** — signing key never leaves hardware
- **TLS** — all traffic encrypted
- **Transcript MACs** — request/response integrity authenticated with HMAC-SHA256
- **Channel binding** — response MAC/signature include TLS certificate fingerprint
- **Pinned server key** — client requires an explicit trusted server key; TOFU is opt-in per command (`--allow-tofu`)
- **Rate limiting** — 5 attempts per source per 60 seconds
- **Audit log** — every request logged with timestamp and source

## License

MIT
