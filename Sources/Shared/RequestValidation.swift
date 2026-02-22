import CryptoKit
import Foundation

/// Result of validating an incoming AuthRequest frame.
public enum ValidatedRequest {
    case test(hostname: String, source: String)
    case auth(nonce: Data, hostname: String, hasStoredKey: Bool, source: String)
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

    // Validate nonce
    guard let nonce = Data(base64Encoded: req.nonce), nonce.count == OTA.nonceSize else {
        throw OTAError.badRequest("invalid nonce")
    }

    // Verify PSK proof
    guard AuthProof.verify(proofBase64: req.clientProof, nonce: nonce, psk: psk) else {
        throw OTAError.authenticationFailed
    }

    // Route by mode
    if req.mode == "test" {
        return .test(hostname: req.hostname, source: source)
    }

    return .auth(nonce: nonce, hostname: req.hostname, hasStoredKey: req.hasStoredKey, source: source)
}
