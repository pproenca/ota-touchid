import CryptoKit
import Foundation
import Network
import Security
import Shared

// MARK: - Public API

public enum ClientCommand {
    /// Authenticate via discovery or direct connection. Calls exit(0/1).
    public static func auth(reason: String, host: String?, port: UInt16?) -> Never {
        Task {
            do {
                let endpoint: NWEndpoint
                if let host, let port {
                    endpoint = NWEndpoint.hostPort(
                        host: NWEndpoint.Host(host),
                        port: NWEndpoint.Port(rawValue: port)!
                    )
                } else {
                    fputs("Discovering server via Bonjour...\n", stderr)
                    endpoint = try await discover()
                    fputs("Found server: \(endpoint)\n", stderr)
                }

                let approved = try await requestAuth(endpoint: endpoint, reason: reason)
                exit(approved ? 0 : 1)
            } catch OTAError.authenticationFailed {
                fputs(
                    "Error: No PSK configured. Run 'ota-touchid setup' first.\n",
                    stderr)
                exit(1)
            } catch {
                fputs("Error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        dispatchMain()
    }

    /// Save a PSK on the client machine.
    public static func pair(pskBase64: String) throws {
        guard let raw = Data(base64Encoded: pskBase64), raw.count == 32 else {
            throw OTAError.badRequest("invalid PSK (expected 32-byte base64)")
        }
        let fm = FileManager.default
        if fm.fileExists(atPath: OTA.pskFile.path) {
            fputs("Existing configuration found. Replacing...\n", stderr)
        }
        try fm.createDirectory(at: OTA.configDir, withIntermediateDirectories: true)
        let tmpFile = OTA.pskFile.deletingLastPathComponent()
            .appendingPathComponent(UUID().uuidString)
        fm.createFile(
            atPath: tmpFile.path,
            contents: pskBase64.data(using: .utf8),
            attributes: [.posixPermissions: 0o600]
        )
        try? fm.removeItem(at: OTA.pskFile)
        try fm.moveItem(at: tmpFile, to: OTA.pskFile)
        print("PSK saved to \(OTA.pskFile.path)")
    }

    /// Manually trust a server public key.
    public static func trustKey(base64: String) throws {
        try storePublicKey(base64)
        print("Server public key stored.")
    }

    /// Show stored server key & PSK status.
    public static func status() {
        do {
            if let key = try loadPublicKey() {
                let fp = keyFingerprint(key.rawRepresentation)
                print("Trusted server key: \(key.rawRepresentation.base64EncodedString())")
                print("Fingerprint: \(fp)")
            } else {
                print("No trusted server key. Will use TOFU on first connection.")
            }
        } catch {
            print("Error reading server key: \(error.localizedDescription)")
        }
        let hasPSK = (try? loadPSK()) != nil
        print("PSK: \(hasPSK ? "configured" : "NOT configured (required)")")
    }

    /// Set up client: try iCloud Keychain first, fall back to manual PSK entry.
    public static func setupClient(pskBase64: String?) throws {
        var psk = pskBase64

        // Try iCloud Keychain if no PSK provided
        if psk == nil {
            if let keychainData = SyncedKeychain.read(account: .preSharedKey),
               let keychainPSK = String(data: keychainData, encoding: .utf8)
            {
                fputs("Found PSK in iCloud Keychain.\n", stderr)
                psk = keychainPSK
            }
        }

        // Fall back to manual prompt
        if psk == nil {
            fputs("Enter PSK from server (base64): ", stderr)
            guard let line = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !line.isEmpty
            else {
                fputs("Error: No PSK provided.\n", stderr)
                exit(1)
            }
            psk = line
        }

        try pair(pskBase64: psk!)

        // Try to get public key from iCloud Keychain (eliminates TOFU)
        if let pubKeyData = SyncedKeychain.read(account: .serverPublicKey),
           let pubKeyBase64 = String(data: pubKeyData, encoding: .utf8)
        {
            try trustKey(base64: pubKeyBase64)
            fputs("Server public key imported from iCloud Keychain (TOFU skipped).\n", stderr)
        }
    }

    /// Test connectivity without triggering Touch ID. Calls exit(0/1).
    public static func test(host: String?, port: UInt16?) -> Never {
        Task {
            do {
                let endpoint: NWEndpoint
                if let host, let port {
                    endpoint = NWEndpoint.hostPort(
                        host: NWEndpoint.Host(host),
                        port: NWEndpoint.Port(rawValue: port)!
                    )
                } else {
                    fputs("Discovering server via Bonjour...\n", stderr)
                    endpoint = try await discover()
                    fputs("Found server: \(endpoint)\n", stderr)
                }

                let ok = try await requestTest(endpoint: endpoint)
                if ok {
                    print("Connection test passed.")
                    exit(0)
                } else {
                    fputs("Connection test failed: server rejected request.\n", stderr)
                    exit(1)
                }
            } catch OTAError.authenticationFailed {
                fputs("Error: No PSK configured. Run 'ota-touchid setup' first.\n", stderr)
                exit(1)
            } catch {
                fputs("Error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        dispatchMain()
    }
}

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
    try? fm.removeItem(at: pubKeyFile)
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
    AuthProof.compute(psk: psk, nonce: nonce)
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

// MARK: - Test Flow (PSK-only, no Touch ID)

private func requestTest(endpoint: NWEndpoint) async throws -> Bool {
    guard let psk = try loadPSK() else {
        throw OTAError.authenticationFailed
    }

    var nonceBytes = [UInt8](repeating: 0, count: OTA.nonceSize)
    guard SecRandomCopyBytes(kSecRandomDefault, OTA.nonceSize, &nonceBytes) == errSecSuccess else {
        throw OTAError.keyGenerationFailed("SecRandomCopyBytes failed")
    }
    let nonce = Data(nonceBytes)
    let proof = computeClientProof(psk: psk, nonce: nonce)

    let request = AuthRequest(
        nonce: nonce,
        reason: "test",
        hasStoredKey: true,
        clientProof: proof,
        mode: "test"
    )
    let frame = try Frame.encode(request)

    let peerInfo = TLSPeerInfo()
    let conn = try await asyncConnect(to: endpoint, using: TLSConfig.clientParameters(peerInfo: peerInfo))
    defer { conn.cancel() }

    try await asyncSend(frame, on: conn)
    let response: AuthResponse = try await asyncReadFrame(AuthResponse.self, on: conn)

    if !response.approved {
        fputs("Server: \(response.error ?? "unknown error")\n", stderr)
    }
    return response.approved
}
