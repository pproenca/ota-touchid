import CryptoKit
import Foundation

/// Result of validating an incoming AuthRequest frame.
public enum ValidatedRequest {
    case test(nonce: Data, hostname: String, source: String)
    case auth(nonce: Data, reason: String, hostname: String, hasStoredKey: Bool, source: String)
}

/// Validates a raw AuthRequest payload. Pure function, no side effects.
/// Returns the validated request or throws with an appropriate OTAError.
public func validateAuthRequest(
    payload: Data,
    psk: SymmetricKey,
    rateLimiter: SourceRateLimiter,
    source: String
) throws -> ValidatedRequest {
    // Rate limiting
    guard rateLimiter.shouldAllow(source: source) else {
        throw OTAError.badRequest("rate limited")
    }

    // Decode
    let req = try Frame.decode(AuthRequest.self, from: payload)
    guard req.version == OTA.protocolVersion else {
        throw OTAError.badRequest("unsupported protocol version \(req.version)")
    }

    // Validate nonce
    guard let nonce = Data(base64Encoded: req.nonce), nonce.count == OTA.nonceSize else {
        throw OTAError.badRequest("invalid nonce")
    }

    let mode = req.mode ?? "auth"
    guard mode == "auth" || mode == "test" else {
        throw OTAError.badRequest("invalid mode")
    }

    // Verify authenticated request transcript
    guard AuthProof.verifyRequestMAC(
        proofBase64: req.requestMAC,
        psk: psk,
        mode: mode,
        nonce: nonce,
        reason: req.reason,
        hostname: req.hostname,
        hasStoredKey: req.hasStoredKey
    ) else {
        throw OTAError.authenticationFailed
    }

    // Route by mode
    if mode == "test" {
        return .test(nonce: nonce, hostname: req.hostname, source: source)
    }

    return .auth(
        nonce: nonce,
        reason: req.reason,
        hostname: req.hostname,
        hasStoredKey: req.hasStoredKey,
        source: source
    )
}
