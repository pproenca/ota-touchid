import Foundation

// MARK: - Constants

public enum OTA {
    public static let serviceType = "_ota-touchid._tcp"
    public static let nonceSize = 32
    public static let maxFrameSize = 65_536
    public static let protocolVersion = 2
    public static let defaultPort: UInt16 = 45_821
    public static let networkTimeoutSeconds: TimeInterval = 5

    public static var configDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/ota-touchid")
    }

    public static var pskFile: URL {
        configDir.appendingPathComponent("psk")
    }

    public static var endpointFile: URL {
        configDir.appendingPathComponent("server.endpoint.json")
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
    case responseVerificationFailed
    case testProofVerificationFailed
    case serverKeyNotTrusted
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
        case .responseVerificationFailed:
            "Response verification failed"
        case .testProofVerificationFailed:
            "Server test proof verification failed"
        case .serverKeyNotTrusted:
            "No trusted server key configured"
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
    public let mode: String?          // "auth" / "test"
    public let nonce: String          // client nonce, base64
    public let reason: String
    public let hostname: String
    public let hasStoredKey: Bool     // tells server whether to include pubkey in response
    public let requestMAC: String?    // HMAC-SHA256 over request transcript, base64
    public let clientProof: String?   // legacy v1 compatibility field

    public init(
        mode: String = "auth",
        nonce: Data,
        reason: String,
        hasStoredKey: Bool = false,
        requestMAC: Data? = nil
    ) {
        self.version = OTA.protocolVersion
        self.mode = mode
        self.nonce = nonce.base64EncodedString()
        self.reason = reason
        self.hostname = ProcessInfo.processInfo.hostName
        self.hasStoredKey = hasStoredKey
        self.requestMAC = requestMAC?.base64EncodedString()
        self.clientProof = nil
    }
}

public struct AuthResponse: Codable, Sendable {
    public let version: Int
    public let mode: String?        // echoes request mode for transcript clarity
    public let approved: Bool
    public let nonceS: String?      // server nonce, base64
    public let signature: String?   // base64
    public let publicKey: String?   // base64 (only sent for TOFU when client lacks key)
    public let responseMAC: String?  // HMAC-SHA256 over response transcript, base64
    public let testProof: String?    // legacy v1 compatibility field
    public let error: String?

    public init(
        mode: String = "auth",
        approved: Bool,
        nonceS: Data? = nil,
        signature: Data? = nil,
        publicKey: Data? = nil,
        responseMAC: Data? = nil,
        error: String? = nil
    ) {
        self.version = OTA.protocolVersion
        self.mode = mode
        self.approved = approved
        self.nonceS = nonceS?.base64EncodedString()
        self.signature = signature?.base64EncodedString()
        self.publicKey = publicKey?.base64EncodedString()
        self.responseMAC = responseMAC?.base64EncodedString()
        self.testProof = nil
        self.error = error
    }
}

public struct EndpointHint: Codable, Sendable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16 = OTA.defaultPort) {
        self.host = host
        self.port = port
    }
}

public struct PairingBundle: Codable, Sendable {
    public static let prefix = "otapair-v1."

    public let version: Int
    public let pskBase64: String
    public let serverPublicKeyBase64: String
    public let endpointHint: EndpointHint?

    public init(
        version: Int = 1,
        pskBase64: String,
        serverPublicKeyBase64: String,
        endpointHint: EndpointHint?
    ) {
        self.version = version
        self.pskBase64 = pskBase64
        self.serverPublicKeyBase64 = serverPublicKeyBase64
        self.endpointHint = endpointHint
    }

    public func encodeToken() throws -> String {
        let data = try JSONEncoder().encode(self)
        return Self.prefix + base64URLEncode(data)
    }

    public static func decodeToken(_ token: String) throws -> PairingBundle {
        guard token.hasPrefix(prefix) else {
            throw OTAError.badRequest("invalid pairing bundle prefix")
        }
        let payload = String(token.dropFirst(prefix.count))
        guard let data = base64URLDecode(payload) else {
            throw OTAError.badRequest("invalid pairing bundle encoding")
        }
        return try JSONDecoder().decode(PairingBundle.self, from: data)
    }
}

private func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func base64URLDecode(_ string: String) -> Data? {
    var s = string
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = s.count % 4
    if remainder != 0 {
        s.append(String(repeating: "=", count: 4 - remainder))
    }
    return Data(base64Encoded: s)
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
        let timeout = DispatchWorkItem {
            guard !resumed else { return }
            resumed = true
            conn.cancel()
            cont.resume(throwing: OTAError.timeout)
        }

        DispatchQueue.main.asyncAfter(
            deadline: .now() + OTA.networkTimeoutSeconds,
            execute: timeout
        )

        conn.stateUpdateHandler = { state in
            guard !resumed else { return }
            switch state {
            case .ready:
                resumed = true
                timeout.cancel()
                cont.resume(returning: conn)
            case .failed(let error):
                resumed = true
                timeout.cancel()
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
        // Safe: all callbacks dispatched to .main, so `resumed` is accessed serially.
        nonisolated(unsafe) var resumed = false
        let timeout = DispatchWorkItem {
            guard !resumed else { return }
            resumed = true
            conn.cancel()
            cont.resume(throwing: OTAError.timeout)
        }
        DispatchQueue.main.asyncAfter(
            deadline: .now() + OTA.networkTimeoutSeconds,
            execute: timeout
        )

        conn.send(content: data, completion: .contentProcessed { error in
            guard !resumed else { return }
            resumed = true
            timeout.cancel()
            if let error {
                cont.resume(throwing: error)
            } else {
                cont.resume()
            }
        })
    }
}

public func asyncReceive(exactly count: Int, on conn: NWConnection) async throws -> Data {
    try await withCheckedThrowingContinuation { cont in
        // Safe: all callbacks dispatched to .main, so `resumed` is accessed serially.
        nonisolated(unsafe) var resumed = false
        let timeout = DispatchWorkItem {
            guard !resumed else { return }
            resumed = true
            conn.cancel()
            cont.resume(throwing: OTAError.timeout)
        }
        DispatchQueue.main.asyncAfter(
            deadline: .now() + OTA.networkTimeoutSeconds,
            execute: timeout
        )

        conn.receive(minimumIncompleteLength: count, maximumLength: count) {
            data, _, _, error in
            guard !resumed else { return }
            resumed = true
            timeout.cancel()
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
