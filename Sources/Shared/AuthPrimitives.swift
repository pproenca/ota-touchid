import CryptoKit
import Foundation

// MARK: - PSK Proof (HMAC-SHA256)

public enum AuthProof {
    public static func compute(psk: SymmetricKey, nonce: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: nonce, using: psk)
        return Data(mac)
    }

    public static func verify(proofBase64: String?, nonce: Data, psk: SymmetricKey) -> Bool {
        guard let proofBase64, let proofData = Data(base64Encoded: proofBase64) else { return false }
        return proofData == compute(psk: psk, nonce: nonce)
    }
}

// MARK: - Source Rate Limiting

public final class SourceRateLimiter {
    private var attempts: [String: (count: Int, resetTime: Date)] = [:]
    private let maxAttempts: Int
    private let windowSeconds: TimeInterval
    private let now: () -> Date

    public init(
        maxAttempts: Int = 5,
        windowSeconds: TimeInterval = 60,
        now: @escaping () -> Date = Date.init
    ) {
        self.maxAttempts = maxAttempts
        self.windowSeconds = windowSeconds
        self.now = now
    }

    public func shouldAllow(source: String) -> Bool {
        let current = now()
        if let entry = attempts[source] {
            if current >= entry.resetTime {
                attempts[source] = (count: 1, resetTime: current.addingTimeInterval(windowSeconds))
                return true
            }
            if entry.count >= maxAttempts {
                return false
            }
            attempts[source] = (count: entry.count + 1, resetTime: entry.resetTime)
            return true
        }

        attempts[source] = (count: 1, resetTime: current.addingTimeInterval(windowSeconds))
        return true
    }
}
