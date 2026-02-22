import CryptoKit
import Foundation

/// Produces a human-readable fingerprint for a public key (16-byte SHA-256 prefix, colon-separated hex).
/// Matches SSH conventions for fingerprint display.
public func keyFingerprint(_ keyData: Data) -> String {
    let hash = SHA256.hash(data: keyData)
    return hash.prefix(16).map { String(format: "%02x", $0) }.joined(separator: ":")
}
