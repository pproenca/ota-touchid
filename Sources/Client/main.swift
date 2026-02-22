import CryptoKit
import Foundation
import Network
import Security
import Shared

// MARK: - Config

private let pubKeyFile = OTA.configDir.appendingPathComponent("server.pub")

private func storePublicKey(_ base64: String) throws {
    guard Data(base64Encoded: base64) != nil else {
        fputs("Error: invalid base64 public key.\n", stderr)
        exit(1)
    }
    try FileManager.default.createDirectory(at: OTA.configDir, withIntermediateDirectories: true)
    try base64.write(to: pubKeyFile, atomically: true, encoding: .utf8)
}

private func loadPublicKey() -> P256.Signing.PublicKey? {
    guard let raw = try? String(contentsOf: pubKeyFile, encoding: .utf8),
        let data = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
        let key = try? P256.Signing.PublicKey(rawRepresentation: data)
    else { return nil }
    return key
}

// MARK: - Async Network Helpers

private enum OTAError: Error, LocalizedError {
    case serverNotFound
    case shortRead
    case timeout

    var errorDescription: String? {
        switch self {
        case .serverNotFound: "No OTA Touch ID server found on local network"
        case .shortRead: "Connection closed unexpectedly"
        case .timeout: "Request timed out"
        }
    }
}

private func discover(timeout: TimeInterval = 5) async throws -> NWEndpoint {
    try await withCheckedThrowingContinuation { cont in
        let browser = NWBrowser(for: .bonjour(type: OTA.serviceType, domain: nil), using: .tcp)
        var done = false

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

private func connect(to endpoint: NWEndpoint) async throws -> NWConnection {
    let conn = NWConnection(to: endpoint, using: .tcp)
    return try await withCheckedThrowingContinuation { cont in
        var done = false
        conn.stateUpdateHandler = { state in
            guard !done else { return }
            switch state {
            case .ready:
                done = true
                cont.resume(returning: conn)
            case .failed(let error):
                done = true
                cont.resume(throwing: error)
            default:
                break
            }
        }
        conn.start(queue: .main)
    }
}

private func send(_ data: Data, on conn: NWConnection) async throws {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        conn.send(content: data, completion: .contentProcessed { error in
            if let error { cont.resume(throwing: error) } else { cont.resume() }
        })
    }
}

private func receive(exactly count: Int, on conn: NWConnection) async throws -> Data {
    try await withCheckedThrowingContinuation { cont in
        conn.receive(minimumIncompleteLength: count, maximumLength: count) {
            data, _, _, error in
            if let data, data.count == count {
                cont.resume(returning: data)
            } else {
                cont.resume(throwing: error ?? OTAError.shortRead)
            }
        }
    }
}

// MARK: - Auth Flow

private func requestAuth(endpoint: NWEndpoint, reason: String) async throws -> Bool {
    // Generate cryptographic nonce
    var nonceBytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &nonceBytes) == errSecSuccess else {
        fputs("Error: failed to generate nonce.\n", stderr)
        return false
    }
    let nonce = Data(nonceBytes)

    let request = AuthRequest(nonce: nonce, reason: reason)
    let frame = try Frame.encode(request)

    // Connect and exchange
    let conn = try await connect(to: endpoint)
    defer { conn.cancel() }

    try await send(frame, on: conn)

    let lenData = try await receive(exactly: 4, on: conn)
    let length = Int(lenData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
    guard (1...65536).contains(length) else { throw OTAError.shortRead }

    let payload = try await receive(exactly: length, on: conn)
    let response = try Frame.decode(AuthResponse.self, from: payload)

    guard response.approved,
        let sigBase64 = response.signature,
        let sigRaw = Data(base64Encoded: sigBase64)
    else {
        fputs("Denied: \(response.error ?? "unknown")\n", stderr)
        return false
    }

    let signature = try P256.Signing.ECDSASignature(rawRepresentation: sigRaw)

    // Verify against stored key
    if let storedKey = loadPublicKey() {
        return storedKey.isValidSignature(signature, for: nonce)
    }

    // TOFU: trust on first use — accept and store the server's public key
    if let pubBase64 = response.publicKey,
        let pubRaw = Data(base64Encoded: pubBase64)
    {
        let key = try P256.Signing.PublicKey(rawRepresentation: pubRaw)
        if key.isValidSignature(signature, for: nonce) {
            try storePublicKey(pubBase64)
            fputs("Trusted server key (first use): \(pubBase64.prefix(16))...\n", stderr)
            return true
        }
    }

    fputs("Signature verification failed.\n", stderr)
    return false
}

// MARK: - CLI

let args = CommandLine.arguments

if args.contains("--help") || args.contains("-h") {
    print("""
        OTA Touch ID Client

        Usage:
          ota-client                              Authenticate via Bonjour discovery
          ota-client --reason "sudo"              Custom reason shown in Touch ID prompt
          ota-client --host <ip> --port <port>    Direct connection (skip Bonjour)
          ota-client --setup <base64-public-key>  Manually trust a server key
          ota-client --status                     Show stored server key

        Exit codes:
          0  Approved (Touch ID succeeded, signature valid)
          1  Denied or error
        """)
    exit(0)
}

if args.contains("--status") {
    if let key = loadPublicKey() {
        print("Trusted server key: \(key.rawRepresentation.base64EncodedString())")
    } else {
        print("No trusted server key. Will use TOFU on first connection.")
    }
    exit(0)
}

if let idx = args.firstIndex(of: "--setup"), idx + 1 < args.count {
    try storePublicKey(args[idx + 1])
    print("Server public key stored.")
    exit(0)
}

let reason: String = {
    if let idx = args.firstIndex(of: "--reason"), idx + 1 < args.count {
        return args[idx + 1]
    }
    return "authentication"
}()

let directHost: String? = {
    if let idx = args.firstIndex(of: "--host"), idx + 1 < args.count {
        return args[idx + 1]
    }
    return nil
}()

let directPort: UInt16? = {
    if let idx = args.firstIndex(of: "--port"), idx + 1 < args.count {
        return UInt16(args[idx + 1])
    }
    return nil
}()

Task {
    do {
        let endpoint: NWEndpoint

        if let host = directHost {
            guard let port = directPort else {
                fputs("--host requires --port\n", stderr)
                exit(1)
            }
            endpoint = .hostPort(
                host: NWEndpoint.Host(host),
                port: NWEndpoint.Port(rawValue: port)!)
        } else {
            fputs("Discovering server via Bonjour...\n", stderr)
            endpoint = try await discover()
            fputs("Found server: \(endpoint)\n", stderr)
        }

        let approved = try await requestAuth(endpoint: endpoint, reason: reason)
        exit(approved ? 0 : 1)
    } catch {
        fputs("Error: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}

dispatchMain()
