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

    @Test("compute returns 32-byte HMAC-SHA256")
    func computeReturns32Bytes() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
        let result = AuthProof.compute(psk: key, nonce: nonce)
        #expect(result.count == 32)  // SHA-256 output is always 32 bytes
    }

    @Test("compute is deterministic for same inputs")
    func computeIsDeterministic() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
        let r1 = AuthProof.compute(psk: key, nonce: nonce)
        let r2 = AuthProof.compute(psk: key, nonce: nonce)
        #expect(r1 == r2)
    }

    @Test("compute differs for different keys")
    func computeDiffersForDifferentKeys() {
        let k1 = SymmetricKey(size: .bits256)
        let k2 = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x01, count: OTA.nonceSize)
        #expect(AuthProof.compute(psk: k1, nonce: nonce) != AuthProof.compute(psk: k2, nonce: nonce))
    }

    @Test("compute differs for different nonces")
    func computeDiffersForDifferentNonces() {
        let key = SymmetricKey(size: .bits256)
        let n1 = Data(repeating: 0x01, count: OTA.nonceSize)
        let n2 = Data(repeating: 0x02, count: OTA.nonceSize)
        #expect(AuthProof.compute(psk: key, nonce: n1) != AuthProof.compute(psk: key, nonce: n2))
    }

    @Test("verify rejects empty-string proof")
    func verifyRejectsEmptyString() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
        #expect(AuthProof.verify(proofBase64: "", nonce: nonce, psk: key) == false)
    }

    @Test("test-mode server proof verifies with matching nonce and cert fingerprint")
    func testModeServerProofRoundTrip() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0xAB, count: OTA.nonceSize)
        let certFP = Data(repeating: 0xCD, count: 32)
        let proof = AuthProof.computeTestServerProof(
            psk: key,
            nonce: nonce,
            certFingerprint: certFP
        )
        let proofBase64 = proof.base64EncodedString()
        #expect(AuthProof.verifyTestServerProof(
            proofBase64: proofBase64,
            psk: key,
            nonce: nonce,
            certFingerprint: certFP
        ))
    }

    @Test("test-mode server proof rejects mismatched nonce or cert fingerprint")
    func testModeServerProofRejectsMismatch() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x01, count: OTA.nonceSize)
        let certFP = Data(repeating: 0x02, count: 32)
        let badNonce = Data(repeating: 0x03, count: OTA.nonceSize)
        let badCertFP = Data(repeating: 0x04, count: 32)
        let proofBase64 = AuthProof.computeTestServerProof(
            psk: key,
            nonce: nonce,
            certFingerprint: certFP
        ).base64EncodedString()

        #expect(AuthProof.verifyTestServerProof(
            proofBase64: proofBase64,
            psk: key,
            nonce: badNonce,
            certFingerprint: certFP
        ) == false)
        #expect(AuthProof.verifyTestServerProof(
            proofBase64: proofBase64,
            psk: key,
            nonce: nonce,
            certFingerprint: badCertFP
        ) == false)
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

    @Test("allows exactly maxAttempts, blocks on maxAttempts+1")
    func exactBudgetBoundary() {
        let limiter = SourceRateLimiter(maxAttempts: 3, windowSeconds: 60) { Date() }
        #expect(limiter.shouldAllow(source: "a"))  // 1
        #expect(limiter.shouldAllow(source: "a"))  // 2
        #expect(limiter.shouldAllow(source: "a"))  // 3
        #expect(limiter.shouldAllow(source: "a") == false)  // 4 = blocked
    }

    @Test("window reset allows a fresh budget")
    func windowResetGivesFreshBudget() {
        var now = Date(timeIntervalSince1970: 1_000_000)
        let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 10) { now }

        #expect(limiter.shouldAllow(source: "x"))       // 1 — allowed
        #expect(limiter.shouldAllow(source: "x") == false)  // 2 — blocked

        // Advance exactly to the window boundary
        now = now.addingTimeInterval(10)
        #expect(limiter.shouldAllow(source: "x"))       // reset, allowed again
        #expect(limiter.shouldAllow(source: "x") == false)  // blocked again
    }

    @Test("sources are fully independent")
    func sourcesAreIndependent() {
        let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 60) { Date() }

        #expect(limiter.shouldAllow(source: "a"))
        #expect(limiter.shouldAllow(source: "a") == false)

        // b is unaffected
        #expect(limiter.shouldAllow(source: "b"))
        #expect(limiter.shouldAllow(source: "b") == false)

        // c is unaffected
        #expect(limiter.shouldAllow(source: "c"))
    }

    @Test("evicts oldest source when maxTrackedSources is reached")
    func evictsOldestTrackedSource() {
        var now = Date(timeIntervalSince1970: 2_000_000)
        let limiter = SourceRateLimiter(
            maxAttempts: 1,
            windowSeconds: 60,
            maxTrackedSources: 2
        ) { now }

        #expect(limiter.shouldAllow(source: "a"))
        #expect(limiter.shouldAllow(source: "a") == false)

        now = now.addingTimeInterval(1)
        #expect(limiter.shouldAllow(source: "b"))
        now = now.addingTimeInterval(1)
        #expect(limiter.shouldAllow(source: "c"))  // evicts oldest tracked source ("a")

        #expect(limiter.shouldAllow(source: "a"))  // fresh after eviction
    }

    @Test("expired entries are pruned before evaluating new sources")
    func prunesExpiredEntries() {
        var now = Date(timeIntervalSince1970: 3_000_000)
        let limiter = SourceRateLimiter(
            maxAttempts: 1,
            windowSeconds: 10,
            maxTrackedSources: 2
        ) { now }

        #expect(limiter.shouldAllow(source: "a"))
        #expect(limiter.shouldAllow(source: "b"))

        now = now.addingTimeInterval(11)  // both entries expired
        #expect(limiter.shouldAllow(source: "c"))
        #expect(limiter.shouldAllow(source: "a"))
    }
}
