import CryptoKit
import Foundation
import Network
import Security
import Shared

// MARK: - Key Storage

private let pubKeyFile = OTA.configDir.appendingPathComponent("server.pub")

private func storePublicKey(_ base64: String) throws {
    guard Data(base64Encoded: base64) != nil else {
        throw OTAError.badRequest("invalid base64 public key")
    }
    let fm = FileManager.default
    try fm.createDirectory(at: OTA.configDir, withIntermediateDirectories: true)
    // [M4] Restrictive permissions — prevent other users from swapping the trusted key.
    let tmpFile = OTA.configDir.appendingPathComponent(UUID().uuidString)
    fm.createFile(
        atPath: tmpFile.path,
        contents: base64.data(using: .utf8),
        attributes: [.posixPermissions: 0o600]
    )
    try fm.moveItem(at: tmpFile, to: pubKeyFile)
}

private func loadPublicKey() throws -> P256.Signing.PublicKey? {
    guard FileManager.default.fileExists(atPath: pubKeyFile.path) else { return nil }
    let raw = try String(contentsOf: pubKeyFile, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = Data(base64Encoded: raw) else {
        throw OTAError.badRequest("stored public key is not valid base64")
    }
    return try P256.Signing.PublicKey(rawRepresentation: data)
}

// MARK: - PSK [C2]

private func loadPSK() throws -> SymmetricKey? {
    let pskFile = OTA.pskFile
    guard FileManager.default.fileExists(atPath: pskFile.path) else { return nil }
    let raw = try String(contentsOf: pskFile, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = Data(base64Encoded: raw), data.count == 32 else {
        throw OTAError.badRequest("stored PSK is invalid (expected 32-byte base64)")
    }
    return SymmetricKey(data: data)
}

private func computeClientProof(psk: SymmetricKey, nonce: Data) -> Data {
    let mac = HMAC<SHA256>.authenticationCode(for: nonce, using: psk)
    return Data(mac)
}

// MARK: - Bonjour Discovery

private func discover(timeout: TimeInterval = 5) async throws -> NWEndpoint {
    try await withCheckedThrowingContinuation { cont in
        let browser = NWBrowser(for: .bonjour(type: OTA.serviceType, domain: nil), using: .tcp)
        // Safe: all callbacks dispatched to .main, so `done` is accessed serially.
        nonisolated(unsafe) var done = false

        browser.browseResultsChangedHandler = { results, _ in
            guard !done, let result = results.first else { return }
            done = true
            browser.cancel()
            cont.resume(returning: result.endpoint)
        }

        browser.stateUpdateHandler = { state in
            if case .failed(let error) = state, !done {
                done = true
                cont.resume(throwing: error)
            }
        }

        browser.start(queue: .main)

        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
            guard !done else { return }
            done = true
            browser.cancel()
            cont.resume(throwing: OTAError.serverNotFound)
        }
    }
}

// MARK: - TOFU Confirmation [H1]

private func confirmTOFU(fingerprint: String) -> Bool {
    fputs(
        """
        \n*** First connection to this server ***
        WARNING: Verify this fingerprint matches the server's output.
        An attacker on the local network could be impersonating the server.
        For high-security environments, use --setup with the server's public key instead.

        Server key fingerprint: \(fingerprint)
        Trust this key? [y/N] \u{0}
        """, stderr)
    guard let line = readLine()?.lowercased() else { return false }
    return line == "y" || line == "yes"
}

// [L5] 16-byte fingerprint matching SSH conventions (was 8 bytes).
private func keyFingerprint(_ keyData: Data) -> String {
    let hash = SHA256.hash(data: keyData)
    return hash.prefix(16).map { String(format: "%02x", $0) }.joined(separator: ":")
}

// MARK: - Auth Flow

private func requestAuth(endpoint: NWEndpoint, reason: String) async throws -> Bool {
    // [C2] PSK is required for client authentication
    guard let psk = try loadPSK() else {
        throw OTAError.authenticationFailed
    }

    // Generate cryptographic nonce
    var nonceBytes = [UInt8](repeating: 0, count: OTA.nonceSize)
    guard SecRandomCopyBytes(kSecRandomDefault, OTA.nonceSize, &nonceBytes) == errSecSuccess else {
        throw OTAError.keyGenerationFailed("SecRandomCopyBytes failed")
    }
    let nonce = Data(nonceBytes)

    let hasStoredKey = (try? loadPublicKey()) != nil
    let proof = computeClientProof(psk: psk, nonce: nonce)

    let request = AuthRequest(
        nonce: nonce,
        reason: reason,
        hasStoredKey: hasStoredKey,
        clientProof: proof
    )
    let frame = try Frame.encode(request)

    // [M2/H2] Capture peer TLS cert fingerprint for channel binding
    let peerInfo = TLSPeerInfo()
    let conn = try await asyncConnect(to: endpoint, using: TLSConfig.clientParameters(peerInfo: peerInfo))
    defer { conn.cancel() }

    try await asyncSend(frame, on: conn)
    let response: AuthResponse = try await asyncReadFrame(AuthResponse.self, on: conn)

    guard response.approved,
        let sigBase64 = response.signature,
        let sigRaw = Data(base64Encoded: sigBase64)
    else {
        fputs("Denied: \(response.error ?? "unknown")\n", stderr)
        return false
    }

    let signature = try P256.Signing.ECDSASignature(rawRepresentation: sigRaw)

    // [M2] Channel binding: verify signature over nonce + TLS cert fingerprint.
    // A MITM with a different TLS certificate produces a different fingerprint,
    // causing signature verification to fail even if they relay to the real server.
    guard let certFP = peerInfo.certFingerprint else {
        throw OTAError.signatureVerificationFailed
    }
    let signedData = nonce + certFP

    // Verify against stored key
    if let storedKey = try loadPublicKey() {
        guard storedKey.isValidSignature(signature, for: signedData) else {
            throw OTAError.signatureVerificationFailed
        }
        return true
    }

    // TOFU: trust on first use — verify signature, then ask user
    guard let pubBase64 = response.publicKey,
        let pubRaw = Data(base64Encoded: pubBase64)
    else {
        throw OTAError.signatureVerificationFailed
    }

    let key = try P256.Signing.PublicKey(rawRepresentation: pubRaw)
    guard key.isValidSignature(signature, for: signedData) else {
        throw OTAError.signatureVerificationFailed
    }

    guard confirmTOFU(fingerprint: keyFingerprint(pubRaw)) else {
        fputs("Connection aborted by user.\n", stderr)
        return false
    }

    try storePublicKey(pubBase64)
    fputs("Server key trusted and stored.\n", stderr)
    return true
}

// MARK: - CLI

private func parseArgs() throws -> (action: Action, reason: String) {
    let args = CommandLine.arguments

    if args.contains("--help") || args.contains("-h") {
        return (.help, "")
    }

    if args.contains("--status") {
        return (.status, "")
    }

    if let idx = args.firstIndex(of: "--setup"), idx + 1 < args.count {
        return (.setup(args[idx + 1]), "")
    }

    let reason: String
    if let idx = args.firstIndex(of: "--reason"), idx + 1 < args.count {
        reason = args[idx + 1]
    } else {
        reason = "authentication"
    }

    if let hostIdx = args.firstIndex(of: "--host"), hostIdx + 1 < args.count {
        let host = args[hostIdx + 1]
        guard let portIdx = args.firstIndex(of: "--port"), portIdx + 1 < args.count else {
            throw OTAError.badRequest("--host requires --port")
        }
        guard let port = UInt16(args[portIdx + 1]) else {
            throw OTAError.invalidPort(args[portIdx + 1])
        }
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!  // UInt16 always valid
        )
        return (.direct(endpoint), reason)
    }

    return (.discover, reason)
}

private enum Action {
    case help
    case status
    case setup(String)
    case discover
    case direct(NWEndpoint)
}

private let helpText = """
    OTA Touch ID Client

    Usage:
      ota-client                              Authenticate via Bonjour discovery
      ota-client --reason "sudo"              Custom reason shown in Touch ID prompt
      ota-client --host <ip> --port <port>    Direct connection (skip Bonjour)
      ota-client --setup <base64-public-key>  Manually trust a server key
      ota-client --status                     Show stored server key & PSK status

    Setup:
      Copy the PSK from the server output to ~/.config/ota-touchid/psk

    Exit codes:
      0  Approved (Touch ID succeeded, signature valid)
      1  Denied or error
    """

// MARK: - Entry Point

do {
    let (action, reason) = try parseArgs()

    switch action {
    case .help:
        print(helpText)
        exit(0)

    case .status:
        if let key = try loadPublicKey() {
            let fp = keyFingerprint(key.rawRepresentation)
            print("Trusted server key: \(key.rawRepresentation.base64EncodedString())")
            print("Fingerprint: \(fp)")
        } else {
            print("No trusted server key. Will use TOFU on first connection.")
        }
        let hasPSK = (try? loadPSK()) != nil
        print("PSK: \(hasPSK ? "configured" : "NOT configured (required)")")
        exit(0)

    case .setup(let base64):
        try storePublicKey(base64)
        print("Server public key stored.")
        exit(0)

    case .discover, .direct:
        Task {
            do {
                let endpoint: NWEndpoint
                if case .direct(let ep) = action {
                    endpoint = ep
                } else {
                    fputs("Discovering server via Bonjour...\n", stderr)
                    endpoint = try await discover()
                    fputs("Found server: \(endpoint)\n", stderr)
                }

                let approved = try await requestAuth(endpoint: endpoint, reason: reason)
                exit(approved ? 0 : 1)
            } catch OTAError.authenticationFailed {
                fputs(
                    "Error: No PSK configured. Copy the PSK from the server to ~/.config/ota-touchid/psk\n",
                    stderr)
                exit(1)
            } catch {
                fputs("Error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        dispatchMain()
    }
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
