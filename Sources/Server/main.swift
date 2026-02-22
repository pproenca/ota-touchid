import CryptoKit
import Foundation
import LocalAuthentication
import Network
import Security
import Shared

// MARK: - Key Management

private let keyFile = OTA.configDir.appendingPathComponent("server.key")

private func loadOrCreateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    let fm = FileManager.default
    try fm.createDirectory(at: OTA.configDir, withIntermediateDirectories: true)

    if let blob = try? Data(contentsOf: keyFile) {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    }

    guard SecureEnclave.isAvailable else {
        throw OTAError.secureEnclaveUnavailable
    }

    var cfError: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &cfError
    ) else {
        throw cfError!.takeRetainedValue()
    }

    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)

    // [M3] Atomic write with unique temp filename to avoid symlink/race attacks.
    let tmpFile = keyFile.deletingLastPathComponent()
        .appendingPathComponent(UUID().uuidString)
    let data = key.dataRepresentation
    fm.createFile(atPath: tmpFile.path, contents: data, attributes: [.posixPermissions: 0o600])
    try fm.moveItem(at: tmpFile, to: keyFile)

    fputs("Created new Secure Enclave key pair.\n", stderr)
    return key
}

// MARK: - PSK (Pre-Shared Key) for Client Authentication [C2]

private func loadOrCreatePSK() throws -> SymmetricKey {
    let fm = FileManager.default
    let pskFile = OTA.pskFile

    if let existing = try? Data(contentsOf: pskFile),
        let raw = Data(
            base64Encoded: String(data: existing, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""),
        raw.count == 32
    {
        return SymmetricKey(data: raw)
    }

    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &bytes) == errSecSuccess else {
        throw OTAError.keyGenerationFailed("SecRandomCopyBytes failed for PSK")
    }
    let key = SymmetricKey(data: Data(bytes))

    let base64 = Data(bytes).base64EncodedString()
    let tmpFile = pskFile.deletingLastPathComponent()
        .appendingPathComponent(UUID().uuidString)
    fm.createFile(
        atPath: tmpFile.path, contents: base64.data(using: .utf8),
        attributes: [.posixPermissions: 0o600])
    try fm.moveItem(at: tmpFile, to: pskFile)

    return key
}

private func verifyClientProof(proof: String?, nonce: Data, psk: SymmetricKey) -> Bool {
    guard let proof, let proofData = Data(base64Encoded: proof) else { return false }
    let expected = HMAC<SHA256>.authenticationCode(for: nonce, using: psk)
    return proofData == Data(expected)
}

// MARK: - Audit Logging [L2]

private let auditFile = OTA.configDir.appendingPathComponent("audit.log")

private func auditLog(_ message: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    let line = "[\(ts)] \(message)\n"
    if let handle = try? FileHandle(forWritingTo: auditFile) {
        handle.seekToEndOfFile()
        handle.write(line.data(using: .utf8) ?? Data())
        handle.closeFile()
    } else {
        FileManager.default.createFile(
            atPath: auditFile.path,
            contents: line.data(using: .utf8),
            attributes: [.posixPermissions: 0o600]
        )
    }
}

// MARK: - Touch ID Signing

private func sign(data: Data, keyBlob: Data, reason: String) async throws
    -> P256.Signing.ECDSASignature
{
    let ctx = LAContext()
    try await ctx.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: reason
    )

    let key = try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: keyBlob,
        authenticationContext: ctx
    )
    return try key.signature(for: data)
}

// MARK: - Rate Limiting [M1]

private final class RateLimiter {
    private var attempts: [String: (count: Int, resetTime: Date)] = [:]
    private let maxAttempts = 5
    private let windowSeconds: TimeInterval = 60

    func shouldAllow(source: String) -> Bool {
        let now = Date()
        if let entry = attempts[source] {
            if now >= entry.resetTime {
                attempts[source] = (count: 1, resetTime: now.addingTimeInterval(windowSeconds))
                return true
            }
            if entry.count >= maxAttempts { return false }
            attempts[source] = (count: entry.count + 1, resetTime: entry.resetTime)
            return true
        }
        attempts[source] = (count: 1, resetTime: now.addingTimeInterval(windowSeconds))
        return true
    }
}

// MARK: - Server

/// All NWListener/NWConnection callbacks are dispatched to `.main`,
/// providing single-threaded access to all server state.
private final class Server: @unchecked Sendable {
    let listener: NWListener
    let keyBlob: Data
    let publicKeyRaw: Data
    let psk: SymmetricKey
    let certFingerprint: Data  // [M2] TLS cert SHA-256 for channel binding
    let rateLimiter = RateLimiter()

    init(
        keyBlob: Data, publicKeyRaw: Data, psk: SymmetricKey, certFingerprint: Data,
        params: NWParameters
    ) throws {
        self.keyBlob = keyBlob
        self.publicKeyRaw = publicKeyRaw
        self.psk = psk
        self.certFingerprint = certFingerprint
        self.listener = try NWListener(using: params)
        listener.service = NWListener.Service(type: OTA.serviceType)
    }

    func start() {
        listener.stateUpdateHandler = { state in
            if case .ready = state, let port = self.listener.port {
                print("Listening on port \(port.rawValue)")
                print("Advertising via Bonjour (\(OTA.serviceType))\n")
                print("Waiting for auth requests...")
            }
        }

        listener.newConnectionHandler = { [weak self] conn in
            conn.start(queue: .main)
            self?.readFrame(conn)
        }

        listener.start(queue: .main)
    }

    // MARK: Framed read

    private func readFrame(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, _, _ in
            guard let self, let data else { conn.cancel(); return }

            let length: Int
            do {
                length = try Frame.readLength(from: data)
            } catch {
                fputs("  frame error: \(error.localizedDescription)\n", stderr)
                conn.cancel()
                return
            }

            self.readPayload(conn, length: length)
        }
    }

    private func readPayload(_ conn: NWConnection, length: Int) {
        conn.receive(minimumIncompleteLength: length, maximumLength: length) {
            [weak self] data, _, _, _ in
            guard let self, let data else { conn.cancel(); return }
            self.handleRequest(data, on: conn)
        }
    }

    // MARK: Connection info [M5]

    private func sourceLabel(for conn: NWConnection) -> String {
        if case .hostPort(let host, let port) = conn.currentPath?.remoteEndpoint {
            return "\(host):\(port)"
        }
        return "unknown"
    }

    // MARK: Request handling

    private func handleRequest(_ data: Data, on conn: NWConnection) {
        let source = sourceLabel(for: conn)

        // [M1] Rate limiting per source
        guard rateLimiter.shouldAllow(source: source) else {
            auditLog("RATE_LIMITED source=\(source)")
            fputs("  rate limited: \(source)\n", stderr)
            reply(.init(approved: false, error: "Rate limited"), on: conn)
            return
        }

        let req: AuthRequest
        let nonce: Data
        do {
            req = try Frame.decode(AuthRequest.self, from: data)
            guard let decoded = Data(base64Encoded: req.nonce), decoded.count == OTA.nonceSize
            else {
                throw OTAError.badRequest("invalid nonce")
            }
            nonce = decoded
        } catch {
            fputs("  bad request from \(source): \(error.localizedDescription)\n", stderr)
            auditLog("BAD_REQUEST source=\(source) error=\(error.localizedDescription)")
            // [L1] Generic error to client
            let clientError = (error as? OTAError)?.clientDescription ?? "Bad request"
            reply(.init(approved: false, error: clientError), on: conn)
            return
        }

        // [C2] Verify client PSK proof before showing Touch ID
        guard verifyClientProof(proof: req.clientProof, nonce: nonce, psk: psk) else {
            fputs("  rejected (bad PSK) from \(source) [\(req.hostname)]\n", stderr)
            auditLog("AUTH_FAILED source=\(source) hostname=\(req.hostname) reason=bad_psk")
            reply(
                .init(approved: false, error: OTAError.authenticationFailed.clientDescription),
                on: conn)
            return
        }

        // [C3/M5] Fixed reason with source IP — never use client-supplied text in Touch ID prompt
        let displayReason = "OTA Touch ID request from \(source)"
        print("\n[\(source)] auth request (client hostname: \(req.hostname))")

        Task {
            do {
                // [M2] Channel binding: sign nonce + TLS cert fingerprint
                let signedData = nonce + self.certFingerprint
                let sig = try await sign(
                    data: signedData,
                    keyBlob: keyBlob,
                    reason: displayReason
                )
                print("  approved")
                auditLog("APPROVED source=\(source) hostname=\(req.hostname)")
                // [H3] Only send public key when client doesn't already have it
                let pubKey: Data? = req.hasStoredKey ? nil : publicKeyRaw
                self.reply(
                    .init(approved: true, signature: sig.rawRepresentation, publicKey: pubKey),
                    on: conn)
            } catch {
                print("  denied (\(error.localizedDescription))")
                auditLog(
                    "DENIED source=\(source) hostname=\(req.hostname) error=\(error.localizedDescription)"
                )
                // [L1] Generic error to client
                reply(.init(approved: false, error: "Authentication denied"), on: conn)
            }
        }
    }

    private func reply(_ response: AuthResponse, on conn: NWConnection) {
        do {
            let frame = try Frame.encode(response)
            conn.send(content: frame, completion: .contentProcessed { _ in conn.cancel() })
        } catch {
            fputs("  encode error: \(error.localizedDescription)\n", stderr)
            conn.cancel()
        }
    }
}

// MARK: - Entry Point

do {
    let key = try loadOrCreateKey()
    let psk = try loadOrCreatePSK()
    let pubRaw = key.publicKey.rawRepresentation

    // [C1] TLS is mandatory — never fall back to plaintext TCP.
    let (params, certFingerprint) = try TLSConfig.serverParameters()
    fputs("TLS enabled.\n", stderr)

    let pskBase64 = psk.withUnsafeBytes { Data($0) }.base64EncodedString()

    print("OTA Touch ID Server")
    print(String(repeating: "\u{2500}", count: 40))
    print("Public key: \(pubRaw.base64EncodedString())")
    print("PSK:        \(pskBase64)")
    print("  Copy the PSK to the client: ~/.config/ota-touchid/psk\n")

    let server = try Server(
        keyBlob: key.dataRepresentation,
        publicKeyRaw: pubRaw,
        psk: psk,
        certFingerprint: certFingerprint,
        params: params
    )
    server.start()

    dispatchMain()
} catch {
    fputs("Fatal: \(error.localizedDescription)\n", stderr)
    exit(1)
}
