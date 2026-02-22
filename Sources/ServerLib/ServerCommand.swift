import CryptoKit
import Foundation
import LocalAuthentication
import Network
import Security
import Shared

// MARK: - Public API

public enum ServerCommand {
    /// Run the server foreground (blocks forever via dispatchMain).
    public static func run() -> Never {
        do {
            let key = try loadOrCreateKey()
            let psk = try loadOrCreatePSK()
            let pubRaw = key.publicKey.rawRepresentation

            // [C1] TLS is mandatory — never fall back to plaintext TCP.
            let (params, certFingerprint) = try TLSConfig.serverParameters()
            logErr("TLS enabled.")

            let pskBase64 = psk.withUnsafeBytes { Data($0) }.base64EncodedString()

            log("OTA Touch ID Server")
            print(String(repeating: "\u{2500}", count: 40))
            log("Public key: \(pubRaw.base64EncodedString())")
            log("PSK:        \(pskBase64)")

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
            logErr("Fatal: \(error.localizedDescription)")
            exit(1)
        }
    }

    /// Generate keys + PSK without starting the listener. Returns PSK and public key as base64.
    public static func generateConfig() throws -> (pskBase64: String, publicKeyBase64: String) {
        let key = try loadOrCreateKey()
        let psk = try loadOrCreatePSK()
        let pskBase64 = psk.withUnsafeBytes { Data($0) }.base64EncodedString()
        let publicKeyBase64 = key.publicKey.rawRepresentation.base64EncodedString()
        return (pskBase64, publicKeyBase64)
    }

    /// Save PSK and public key to iCloud Keychain for auto-pairing.
    public static func publishToKeychain(pskBase64: String, publicKeyBase64: String) throws {
        guard let pskData = pskBase64.data(using: .utf8),
              let pubKeyData = publicKeyBase64.data(using: .utf8)
        else { return }
        try SyncedKeychain.save(account: .preSharedKey, data: pskData)
        try SyncedKeychain.save(account: .serverPublicKey, data: pubKeyData)
    }
}

// MARK: - Timestamped Logging

private let logDateFormatter: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

private func log(_ message: String) {
    print("[\(logDateFormatter.string(from: Date()))] \(message)")
}

private func logErr(_ message: String) {
    fputs("[\(logDateFormatter.string(from: Date()))] \(message)\n", stderr)
}

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

    logErr("Created new Secure Enclave key pair.")
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

// MARK: - Server

/// All NWListener/NWConnection callbacks are dispatched to `.main`,
/// providing single-threaded access to all server state.
private final class Server: @unchecked Sendable {
    let listener: NWListener
    let keyBlob: Data
    let publicKeyRaw: Data
    let psk: SymmetricKey
    let certFingerprint: Data  // [M2] TLS cert SHA-256 for channel binding
    let rateLimiter = SourceRateLimiter()

    init(
        keyBlob: Data, publicKeyRaw: Data, psk: SymmetricKey, certFingerprint: Data,
        params: NWParameters
    ) throws {
        self.keyBlob = keyBlob
        self.publicKeyRaw = publicKeyRaw
        self.psk = psk
        self.certFingerprint = certFingerprint
        guard let port = NWEndpoint.Port(rawValue: OTA.defaultPort) else {
            throw OTAError.invalidPort("\(OTA.defaultPort)")
        }
        self.listener = try NWListener(using: params, on: port)
        listener.service = NWListener.Service(type: OTA.serviceType)
    }

    func start() {
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = self.listener.port else { return }
                log("Listening on port \(port.rawValue)")
                log("Advertising via Bonjour (\(OTA.serviceType))")
                log("Waiting for auth requests...")
            case .waiting(let error):
                logErr("Listener waiting: \(error.localizedDescription)")
            case .failed(let error):
                logErr("Listener failed: \(error.localizedDescription)")
                auditLog("LISTENER_FAILED error=\(error.localizedDescription)")
                self.listener.cancel()
                // Let launchd KeepAlive restart the process.
                exit(1)
            case .cancelled:
                logErr("Listener cancelled.")
            default:
                break
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
        receiveExactly(4, on: conn) { [weak self] result in
            guard let self else { conn.cancel(); return }

            let data: Data
            switch result {
            case .success(let payload):
                data = payload
            case .failure(let error):
                logErr("  frame read error: \(error.localizedDescription)")
                conn.cancel()
                return
            }

            let length: Int
            do {
                length = try Frame.readLength(from: data)
            } catch {
                logErr("  frame error: \(error.localizedDescription)")
                conn.cancel()
                return
            }

            self.readPayload(conn, length: length)
        }
    }

    private func readPayload(_ conn: NWConnection, length: Int) {
        receiveExactly(length, on: conn) { [weak self] result in
            guard let self else { conn.cancel(); return }
            switch result {
            case .success(let data):
                self.handleRequest(data, on: conn)
            case .failure(let error):
                logErr("  payload read error: \(error.localizedDescription)")
                conn.cancel()
            }
        }
    }

    private func receiveExactly(
        _ count: Int,
        on conn: NWConnection,
        timeout: TimeInterval = OTA.networkTimeoutSeconds,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        // Safe: callbacks run on `.main`, so `done` is serially accessed.
        nonisolated(unsafe) var done = false
        let timeoutItem = DispatchWorkItem {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(.failure(OTAError.timeout))
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: timeoutItem)

        conn.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
            guard !done else { return }
            done = true
            timeoutItem.cancel()
            if let data, data.count == count {
                completion(.success(data))
            } else {
                completion(.failure(error ?? OTAError.shortRead))
            }
        }
    }

    // MARK: Connection info [M5]

    private func sourceLabel(for conn: NWConnection) -> String {
        if case .hostPort(let host, _) = conn.currentPath?.remoteEndpoint {
            return "\(host)"
        }
        return "unknown"
    }

    // MARK: Request handling

    private func handleRequest(_ data: Data, on conn: NWConnection) {
        let source = sourceLabel(for: conn)

        let validated: ValidatedRequest
        do {
            validated = try validateAuthRequest(
                payload: data,
                psk: psk,
                rateLimiter: rateLimiter,
                source: source
            )
        } catch let error as OTAError where error.clientDescription == "Authentication failed" {
            logErr("  rejected (bad PSK) from \(source)")
            auditLog("AUTH_FAILED source=\(source) reason=bad_psk")
            reply(.init(approved: false, error: error.clientDescription), on: conn)
            return
        } catch {
            logErr("  bad request from \(source): \(error.localizedDescription)")
            auditLog("BAD_REQUEST source=\(source) error=\(error.localizedDescription)")
            let clientError = (error as? OTAError)?.clientDescription ?? "Bad request"
            reply(.init(approved: false, error: clientError), on: conn)
            return
        }

        switch validated {
        case .test(let nonce, let hostname, _):
            log("[\(source)] test request (client hostname: \(hostname)) — OK")
            auditLog("TEST_OK source=\(source) hostname=\(hostname)")
            let nonceS: Data
            do {
                nonceS = try randomNonce()
            } catch {
                logErr("  nonce generation failed: \(error.localizedDescription)")
                reply(.init(mode: "test", approved: false, error: "Internal server error"), on: conn)
                return
            }
            let responseMAC = AuthProof.computeResponseMAC(
                psk: psk,
                mode: "test",
                nonceC: nonce,
                nonceS: nonceS,
                approved: true,
                signature: nil,
                error: nil,
                certFingerprint: certFingerprint
            )
            reply(
                .init(mode: "test", approved: true, nonceS: nonceS, responseMAC: responseMAC),
                on: conn
            )

        case .auth(let nonce, let reason, let hostname, let hasStoredKey, _):
            let trimmedReason = reason.trimmingCharacters(in: .whitespacesAndNewlines)
            let displayReason = trimmedReason.isEmpty
                ? "OTA Touch ID request from \(source)"
                : "OTA Touch ID: \(String(trimmedReason.prefix(80)))"
            log("[\(source)] auth request (client hostname: \(hostname))")
            let nonceS: Data
            do {
                nonceS = try randomNonce()
            } catch {
                logErr("  nonce generation failed: \(error.localizedDescription)")
                reply(.init(mode: "auth", approved: false, error: "Internal server error"), on: conn)
                return
            }

            Task {
                do {
                    let signedData = AuthProof.authSignaturePayload(
                        nonceC: nonce,
                        nonceS: nonceS,
                        approved: true,
                        reason: reason,
                        certFingerprint: self.certFingerprint
                    )
                    let sig = try await sign(
                        data: signedData,
                        keyBlob: keyBlob,
                        reason: displayReason
                    )
                    log("  approved")
                    auditLog("APPROVED source=\(source) hostname=\(hostname)")
                    let pubKey: Data? = hasStoredKey ? nil : publicKeyRaw
                    let responseMAC = AuthProof.computeResponseMAC(
                        psk: self.psk,
                        mode: "auth",
                        nonceC: nonce,
                        nonceS: nonceS,
                        approved: true,
                        signature: sig.rawRepresentation,
                        error: nil,
                        certFingerprint: self.certFingerprint
                    )
                    self.reply(
                        .init(
                            mode: "auth",
                            approved: true,
                            nonceS: nonceS,
                            signature: sig.rawRepresentation,
                            publicKey: pubKey,
                            responseMAC: responseMAC
                        ),
                        on: conn)
                } catch {
                    log("  denied (\(error.localizedDescription))")
                    auditLog("DENIED source=\(source) hostname=\(hostname) error=\(error.localizedDescription)")
                    let deniedError = "Authentication denied"
                    let responseMAC = AuthProof.computeResponseMAC(
                        psk: self.psk,
                        mode: "auth",
                        nonceC: nonce,
                        nonceS: nonceS,
                        approved: false,
                        signature: nil,
                        error: deniedError,
                        certFingerprint: self.certFingerprint
                    )
                    reply(
                        .init(
                            mode: "auth",
                            approved: false,
                            nonceS: nonceS,
                            responseMAC: responseMAC,
                            error: deniedError
                        ),
                        on: conn
                    )
                }
            }
        }
    }

    private func reply(_ response: AuthResponse, on conn: NWConnection) {
        do {
            let frame = try Frame.encode(response)
            conn.send(content: frame, completion: .contentProcessed { _ in conn.cancel() })
        } catch {
            logErr("  encode error: \(error.localizedDescription)")
            conn.cancel()
        }
    }
}

private func randomNonce() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: OTA.nonceSize)
    guard SecRandomCopyBytes(kSecRandomDefault, OTA.nonceSize, &bytes) == errSecSuccess else {
        throw OTAError.keyGenerationFailed("SecRandomCopyBytes failed")
    }
    return Data(bytes)
}
