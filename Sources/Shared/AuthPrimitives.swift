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
        return constantTimeEqual(proofData, compute(psk: psk, nonce: nonce))
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }

        var diff: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            diff |= left ^ right
        }
        return diff == 0
    }
}

// MARK: - Source Rate Limiting

public final class SourceRateLimiter {
    private struct Entry {
        var count: Int
        let resetTime: Date
    }

    private var attempts: [String: Entry] = [:]
    private let maxAttempts: Int
    private let windowSeconds: TimeInterval
    private let maxTrackedSources: Int
    private let now: () -> Date

    public init(
        maxAttempts: Int = 5,
        windowSeconds: TimeInterval = 60,
        maxTrackedSources: Int = 1_024,
        now: @escaping () -> Date = Date.init
    ) {
        self.maxAttempts = maxAttempts
        self.windowSeconds = windowSeconds
        self.maxTrackedSources = maxTrackedSources
        self.now = now
    }

    public func shouldAllow(source: String) -> Bool {
        let current = now()

        // Drop stale windows so memory stays bounded under long-running attack traffic.
        attempts = attempts.filter { current < $0.value.resetTime }

        if let entry = attempts[source] {
            if entry.count >= maxAttempts {
                return false
            }
            attempts[source] = Entry(count: entry.count + 1, resetTime: entry.resetTime)
            return true
        }

        if attempts.count >= maxTrackedSources,
            let oldestSource = attempts.min(by: { $0.value.resetTime < $1.value.resetTime })?.key
        {
            attempts.removeValue(forKey: oldestSource)
        }

        attempts[source] = Entry(count: 1, resetTime: current.addingTimeInterval(windowSeconds))
        return true
    }
}
