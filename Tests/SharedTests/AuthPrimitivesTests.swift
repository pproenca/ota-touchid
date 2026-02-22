import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Auth proof")
struct AuthProofTests {
    @Test("verify accepts valid base64 proof")
    func verifyAcceptsValidProof() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
        let proof = AuthProof.compute(psk: key, nonce: nonce).base64EncodedString()

        #expect(AuthProof.verify(proofBase64: proof, nonce: nonce, psk: key))
    }

    @Test("verify rejects nil, malformed, and mismatched proof")
    func verifyRejectsInvalidProofs() {
        let key = SymmetricKey(size: .bits256)
        let otherKey = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x11, count: OTA.nonceSize)
        let otherNonce = Data(repeating: 0x22, count: OTA.nonceSize)
        let validProof = AuthProof.compute(psk: key, nonce: nonce).base64EncodedString()

        #expect(AuthProof.verify(proofBase64: nil, nonce: nonce, psk: key) == false)
        #expect(AuthProof.verify(proofBase64: "not-base64", nonce: nonce, psk: key) == false)
        #expect(AuthProof.verify(proofBase64: validProof, nonce: otherNonce, psk: key) == false)
        #expect(AuthProof.verify(proofBase64: validProof, nonce: nonce, psk: otherKey) == false)
    }
}

@Suite("Source rate limiter")
struct SourceRateLimiterTests {
    @Test("enforces attempt budget per source")
    func enforcesBudget() {
        var now = Date(timeIntervalSince1970: 1_700_000_000)
        let limiter = SourceRateLimiter(maxAttempts: 2, windowSeconds: 60) { now }

        #expect(limiter.shouldAllow(source: "10.0.0.1"))
        #expect(limiter.shouldAllow(source: "10.0.0.1"))
        #expect(limiter.shouldAllow(source: "10.0.0.1") == false)

        // Different source has an independent budget.
        #expect(limiter.shouldAllow(source: "10.0.0.2"))

        // Move beyond the window and confirm the source can retry.
        now = now.addingTimeInterval(61)
        #expect(limiter.shouldAllow(source: "10.0.0.1"))
    }
}
