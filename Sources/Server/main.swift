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
        fputs("Error: Secure Enclave not available on this Mac.\n", stderr)
        exit(1)
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
    try key.dataRepresentation.write(to: keyFile)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)

    fputs("Created new Secure Enclave key pair.\n", stderr)
    return key
}

// MARK: - Touch ID Signing

/// Each call creates a fresh LAContext so every request triggers its own Touch ID prompt.
private func sign(nonce: Data, keyBlob: Data, reason: String) async throws
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
    return try key.signature(for: nonce)
}

// MARK: - TCP Server

private final class Server {
    let listener: NWListener
    let keyBlob: Data
    let publicKeyRaw: Data

    init(keyBlob: Data, publicKeyRaw: Data) throws {
        self.keyBlob = keyBlob
        self.publicKeyRaw = publicKeyRaw
        self.listener = try NWListener(using: .tcp)
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
            self?.readLength(conn)
        }

        listener.start(queue: .main)
    }

    // -- Framed read: 4-byte length then payload --

    private func readLength(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, _, _ in
            guard let self, let data, data.count == 4 else { conn.cancel(); return }
            let len = Int(data.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
            guard (1...65536).contains(len) else { conn.cancel(); return }
            self.readPayload(conn, length: len)
        }
    }

    private func readPayload(_ conn: NWConnection, length: Int) {
        conn.receive(minimumIncompleteLength: length, maximumLength: length) {
            [weak self] data, _, _, _ in
            guard let self, let data else { conn.cancel(); return }
            self.handleRequest(data, on: conn)
        }
    }

    // -- Auth request handling --

    private func handleRequest(_ data: Data, on conn: NWConnection) {
        guard let req = try? Frame.decode(AuthRequest.self, from: data),
            let nonce = Data(base64Encoded: req.nonce),
            nonce.count == 32
        else {
            reply(.init(approved: false, error: "bad request"), on: conn)
            return
        }

        print("\n[\(req.hostname)] auth request (reason: \(req.reason))")

        Task {
            do {
                let sig = try await sign(
                    nonce: nonce,
                    keyBlob: keyBlob,
                    reason: "\(req.hostname): \(req.reason)"
                )
                print("  approved")
                await MainActor.run {
                    self.reply(
                        .init(
                            approved: true,
                            signature: sig.rawRepresentation,
                            publicKey: self.publicKeyRaw
                        ), on: conn)
                }
            } catch {
                print("  denied (\(error.localizedDescription))")
                await MainActor.run {
                    self.reply(.init(approved: false, error: error.localizedDescription), on: conn)
                }
            }
        }
    }

    private func reply(_ response: AuthResponse, on conn: NWConnection) {
        guard let frame = try? Frame.encode(response) else { conn.cancel(); return }
        conn.send(content: frame, completion: .contentProcessed { _ in conn.cancel() })
    }
}

// MARK: - Entry Point

do {
    let key = try loadOrCreateKey()
    let pubRaw = key.publicKey.rawRepresentation

    print("OTA Touch ID Server")
    print(String(repeating: "─", count: 40))
    print("Public key: \(pubRaw.base64EncodedString())\n")

    let server = try Server(keyBlob: key.dataRepresentation, publicKeyRaw: pubRaw)
    server.start()

    dispatchMain()
} catch {
    fputs("Failed to start: \(error)\n", stderr)
    exit(1)
}
