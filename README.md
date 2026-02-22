# ota-touchid

Over-the-air Touch ID authentication for remote Macs. Press Touch ID on the client Mac, and the server verifies that biometric-backed assertion over the local network.

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
- Touch ID (client Mac that runs `auth`/`enroll`)

## Quick start

On the server Mac:

```bash
ota-touchid setup --server
```

This installs the launchd service and prints a one-line pairing token.

On the client Mac (where you will press Touch ID):

```bash
ota-touchid pair <pairing-bundle>
ota-touchid enroll
ota-touchid test
ota-touchid auth --reason sudo
```

## Commands

| Command | What it does |
|---|---|
| `setup` | Generate keys, install server as launchd agent |
| `pair <pairing-bundle\|psk>` / `pair --stdin` | Import pairing data on client |
| `trust <server-public-key-base64>` | Pin trusted server key on client |
| `enroll` | Register client Touch ID-backed key on server |
| `auth` | Authenticate via Touch ID (exit 0=ok, 1=denied) |
| `test` | Verify secure connectivity and server authenticity |
| `serve` | Run server in foreground |
| `status` | Show config & service status |
| `uninstall` | Stop service, remove launchd agent |

### Auth options

```
--reason <text>             Reason shown in client Touch ID prompt (default: "authentication")
--host <ip-or-hostname>     Direct connection (skip Bonjour discovery)
--port <port>               Optional with --host (default: 45821)
--allow-tofu                Explicitly allow trust-on-first-use for this connection
```

## How it works

1. **Server** runs as a launchd agent. On `setup`, it creates a Secure Enclave identity key and a PSK.

2. **Client** imports the pairing bundle and runs `enroll`, which creates a Touch ID-protected Secure Enclave key on the client and registers its public key on the server.

3. **Client auth** (`ota-touchid auth`) prompts Touch ID on the client, signs a channel-bound transcript, and sends that signature plus HMAC-authenticated request data.

4. **Server** verifies the enrolled client key signature, then returns a server-signed response; the client verifies response MAC + server signature against its pinned server key.

All traffic is TLS-encrypted with channel binding to prevent MITM attacks. The server rate-limits requests and logs every authentication event to `~/.config/ota-touchid/audit.log`.

## Security

- **Secure Enclave** — signing key never leaves hardware
- **TLS** — all traffic encrypted
- **Transcript MACs** — request/response integrity authenticated with HMAC-SHA256
- **Channel binding** — response MAC/signature include TLS certificate fingerprint
- **Enrolled client key** — server only accepts assertions from a previously enrolled client public key
- **Pinned server key** — client requires an explicit trusted server key; TOFU is opt-in per command (`--allow-tofu`)
- **Rate limiting** — 5 attempts per source per 60 seconds
- **Audit log** — every request logged with timestamp and source

## License

MIT
