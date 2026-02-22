import Foundation

// MARK: - Constants

public enum OTA {
    public static let serviceType = "_ota-touchid._tcp"

    public static var configDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/ota-touchid")
    }
}

// MARK: - Messages

public struct AuthRequest: Codable, Sendable {
    public let nonce: String      // base64
    public let reason: String
    public let hostname: String

    public init(nonce: Data, reason: String) {
        self.nonce = nonce.base64EncodedString()
        self.reason = reason
        self.hostname = ProcessInfo.processInfo.hostName
    }
}

public struct AuthResponse: Codable, Sendable {
    public let approved: Bool
    public let signature: String?  // base64
    public let publicKey: String?  // base64 (sent for TOFU)
    public let error: String?

    public init(
        approved: Bool,
        signature: Data? = nil,
        publicKey: Data? = nil,
        error: String? = nil
    ) {
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

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try JSONDecoder().decode(type, from: data)
    }
}
