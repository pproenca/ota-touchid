import Foundation

// MARK: - Constants

public enum OTA {
    public static let serviceType = "_ota-touchid._tcp"
    public static let nonceSize = 32
    public static let maxFrameSize = 65_536
    public static let protocolVersion = 1

    public static var configDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/ota-touchid")
    }

    public static var pskFile: URL {
        configDir.appendingPathComponent("psk")
    }
}

// MARK: - Errors

public enum OTAError: Error, LocalizedError, Sendable {
    case secureEnclaveUnavailable
    case keyGenerationFailed(String)
    case badRequest(String)
    case serverNotFound
    case shortRead
    case timeout
    case frameTooLarge(Int)
    case signatureVerificationFailed
    case invalidPort(String)
    case authenticationFailed

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            "Secure Enclave not available on this Mac"
        case .keyGenerationFailed(let d):
            "Key generation failed: \(d)"
        case .badRequest(let d):
            "Bad request: \(d)"
        case .serverNotFound:
            "No OTA Touch ID server found on local network"
        case .shortRead:
            "Connection closed unexpectedly"
        case .timeout:
            "Request timed out"
        case .frameTooLarge(let n):
            "Frame too large: \(n) bytes (max \(OTA.maxFrameSize))"
        case .signatureVerificationFailed:
            "Signature verification failed"
        case .invalidPort(let v):
            "Invalid port: \(v)"
        case .authenticationFailed:
            "Client authentication failed"
        }
    }

    /// Generic description safe to send to untrusted clients (avoids leaking internals).
    public var clientDescription: String {
        switch self {
        case .secureEnclaveUnavailable, .keyGenerationFailed:
            "Internal server error"
        case .badRequest:
            "Bad request"
        case .frameTooLarge:
            "Request too large"
        case .authenticationFailed:
            "Authentication failed"
        default:
            "Request denied"
        }
    }
}

// MARK: - Messages

public struct AuthRequest: Codable, Sendable {
    public let version: Int
    public let nonce: String         // base64
    public let reason: String
    public let hostname: String
    public let hasStoredKey: Bool     // tells server whether to include pubkey in response
    public let clientProof: String?  // HMAC-SHA256(PSK, nonce), base64
    public let mode: String?         // nil/"auth" = normal, "test" = PSK-only check

    public init(
        nonce: Data,
        reason: String,
        hasStoredKey: Bool = false,
        clientProof: Data? = nil,
        mode: String? = nil
    ) {
        self.version = OTA.protocolVersion
        self.nonce = nonce.base64EncodedString()
        self.reason = reason
        self.hostname = ProcessInfo.processInfo.hostName
        self.hasStoredKey = hasStoredKey
        self.clientProof = clientProof?.base64EncodedString()
        self.mode = mode
    }
}

public struct AuthResponse: Codable, Sendable {
    public let version: Int
    public let approved: Bool
    public let signature: String?   // base64
    public let publicKey: String?   // base64 (only sent for TOFU when client lacks key)
    public let error: String?

    public init(
        approved: Bool,
        signature: Data? = nil,
        publicKey: Data? = nil,
        error: String? = nil
    ) {
        self.version = OTA.protocolVersion
        self.approved = approved
        self.signature = signature?.base64EncodedString()
        self.publicKey = publicKey?.base64EncodedString()
        self.error = error
    }
}

// MARK: - Length-prefixed framing (4-byte big-endian + JSON)

public enum Frame {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let json = try JSONEncoder().encode(value)
        var len = UInt32(json.count).bigEndian
        var out = Data(bytes: &len, count: 4)
        out.append(json)
        return out
    }

    public static func readLength(from header: Data) throws -> Int {
        guard header.count >= 4 else { throw OTAError.shortRead }
        let len = Int(header.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
        guard (1...OTA.maxFrameSize).contains(len) else {
            throw OTAError.frameTooLarge(len)
        }
        return len
    }

    public static func decode<T: Decodable>(_ type: T.Type, from payload: Data) throws -> T {
        try JSONDecoder().decode(type, from: payload)
    }
}

// MARK: - NWConnection async helpers

import Network

public func asyncConnect(to endpoint: NWEndpoint, using params: NWParameters) async throws
    -> NWConnection
{
    let conn = NWConnection(to: endpoint, using: params)
    return try await withCheckedThrowingContinuation { cont in
        // Safe: all callbacks dispatched to .main, so `resumed` is accessed serially.
        nonisolated(unsafe) var resumed = false
        conn.stateUpdateHandler = { state in
            guard !resumed else { return }
            switch state {
            case .ready:
                resumed = true
                cont.resume(returning: conn)
            case .failed(let error):
                resumed = true
                cont.resume(throwing: error)
            default:
                break
            }
        }
        conn.start(queue: .main)
    }
}

public func asyncSend(_ data: Data, on conn: NWConnection) async throws {
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        conn.send(content: data, completion: .contentProcessed { error in
            if let error { cont.resume(throwing: error) } else { cont.resume() }
        })
    }
}

public func asyncReceive(exactly count: Int, on conn: NWConnection) async throws -> Data {
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

/// Reads a full length-prefixed frame from the connection.
public func asyncReadFrame<T: Decodable>(
    _ type: T.Type, on conn: NWConnection
) async throws -> T {
    let header = try await asyncReceive(exactly: 4, on: conn)
    let length = try Frame.readLength(from: header)
    let payload = try await asyncReceive(exactly: length, on: conn)
    return try Frame.decode(type, from: payload)
}
