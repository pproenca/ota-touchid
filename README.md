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

This generates keys, creates a PSK, and installs a launchd agent. Copy the PSK from the output.

On the remote Mac (client):

```bash
ota-touchid pair <psk>
ota-touchid auth --reason sudo
```

## Commands

| Command | What it does |
|---|---|
| `setup` | Generate keys, install server as launchd agent |
| `pair <psk>` | Save PSK on client machine |
| `auth` | Authenticate via Touch ID (exit 0=ok, 1=denied) |
| `serve` | Run server in foreground |
| `status` | Show config & service status |
| `uninstall` | Stop service, remove launchd agent |

### Auth options

```
--reason <text>              Reason shown in Touch ID prompt (default: "authentication")
--host <ip> --port <port>    Direct connection (skip Bonjour discovery)
```

## How it works

1. **Server** runs on a Mac with Touch ID. On `setup`, it creates a P256 key pair in the Secure Enclave and a pre-shared key (PSK) for client authentication.

2. **Client** discovers the server via Bonjour (or connects directly). It proves it knows the PSK, then requests authentication.

3. **Server** shows a Touch ID prompt. On approval, it signs the client's nonce with the Secure Enclave key and returns the signature.

4. **Client** verifies the signature against the stored public key (TOFU on first connection) and exits 0 (approved) or 1 (denied).

All traffic is TLS-encrypted with channel binding to prevent MITM attacks. The server rate-limits requests and logs every authentication event to `~/.config/ota-touchid/audit.log`.

## Security

- **Secure Enclave** — signing key never leaves hardware
- **TLS** — all traffic encrypted, channel binding via certificate fingerprint
- **PSK authentication** — clients must prove possession of the pre-shared key before Touch ID is triggered
- **TOFU** — trust-on-first-use with fingerprint verification (like SSH)
- **Rate limiting** — 5 attempts per source per 60 seconds
- **Audit log** — every request logged with timestamp and source

## License

MIT
