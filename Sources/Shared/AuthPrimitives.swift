import CryptoKit
import Foundation

// MARK: - Protocol v2 transcript auth (HMAC-SHA256)

public enum AuthProof {
    private static let requestContext = Data("ota-touchid:req:v2".utf8)
    private static let responseContext = Data("ota-touchid:resp:v2".utf8)
    private static let clientSignatureContext = Data("ota-touchid:clientsig:v2".utf8)
    private static let serverSignatureContext = Data("ota-touchid:serversig:v2".utf8)

    public static func computeRequestMAC(
        psk: SymmetricKey,
        mode: String,
        nonce: Data,
        reason: String,
        hostname: String,
        hasStoredKey: Bool
    ) -> Data {
        let payload = transcript(
            context: requestContext,
            fields: [
                Data(mode.utf8),
                nonce,
                digest(reason),
                digest(hostname),
                Data([hasStoredKey ? 1 : 0]),
            ]
        )
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: psk)
        return Data(mac)
    }

    public static func verifyRequestMAC(
        proofBase64: String?,
        psk: SymmetricKey,
        mode: String,
        nonce: Data,
        reason: String,
        hostname: String,
        hasStoredKey: Bool
    ) -> Bool {
        guard let proofBase64, let proofData = Data(base64Encoded: proofBase64) else { return false }
        let expected = computeRequestMAC(
            psk: psk,
            mode: mode,
            nonce: nonce,
            reason: reason,
            hostname: hostname,
            hasStoredKey: hasStoredKey
        )
        return constantTimeEqual(proofData, expected)
    }

    public static func computeResponseMAC(
        psk: SymmetricKey,
        mode: String,
        nonceC: Data,
        nonceS: Data,
        approved: Bool,
        signature: Data?,
        error: String?,
        certFingerprint: Data
    ) -> Data {
        let payload = transcript(
            context: responseContext,
            fields: [
                Data(mode.utf8),
                nonceC,
                nonceS,
                Data([approved ? 1 : 0]),
                digest(signature ?? Data()),
                digest(Data((error ?? "").utf8)),
                certFingerprint,
            ]
        )
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: psk)
        return Data(mac)
    }

    public static func verifyResponseMAC(
        proofBase64: String?,
        psk: SymmetricKey,
        mode: String,
        nonceC: Data,
        nonceS: Data,
        approved: Bool,
        signature: Data?,
        error: String?,
        certFingerprint: Data
    ) -> Bool {
        guard let proofBase64, let proofData = Data(base64Encoded: proofBase64) else { return false }
        let expected = computeResponseMAC(
            psk: psk,
            mode: mode,
            nonceC: nonceC,
            nonceS: nonceS,
            approved: approved,
            signature: signature,
            error: error,
            certFingerprint: certFingerprint
        )
        return constantTimeEqual(proofData, expected)
    }

    /// Transcript that a client signs (after local Touch ID) to prove user presence.
    public static func clientSignaturePayload(
        mode: String,
        nonce: Data,
        reason: String,
        hostname: String,
        certFingerprint: Data
    ) -> Data {
        transcript(
            context: clientSignatureContext,
            fields: [
                Data(mode.utf8),
                nonce,
                digest(reason),
                digest(hostname),
                certFingerprint,
            ]
        )
    }

    /// Transcript that the server signs to prove server identity.
    public static func serverSignaturePayload(
        mode: String,
        nonceC: Data,
        nonceS: Data,
        approved: Bool,
        reason: String,
        certFingerprint: Data
    ) -> Data {
        transcript(
            context: serverSignatureContext,
            fields: [
                Data(mode.utf8),
                nonceC,
                nonceS,
                Data([approved ? 1 : 0]),
                digest(reason),
                certFingerprint,
            ]
        )
    }

    /// Backward-compat shim for existing call sites/tests.
    public static func authSignaturePayload(
        nonceC: Data,
        nonceS: Data,
        approved: Bool,
        reason: String,
        certFingerprint: Data
    ) -> Data {
        serverSignaturePayload(
            mode: "auth",
            nonceC: nonceC,
            nonceS: nonceS,
            approved: approved,
            reason: reason,
            certFingerprint: certFingerprint
        )
    }

    private static func transcript(context: Data, fields: [Data]) -> Data {
        var data = context
        for field in fields {
            var len = UInt32(field.count).bigEndian
            data.append(Data(bytes: &len, count: 4))
            data.append(field)
        }
        return data
    }

    private static func digest(_ string: String) -> Data {
        digest(Data(string.utf8))
    }

    private static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
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
