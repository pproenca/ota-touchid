import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Auth proof")
struct AuthProofTests {
    @Test("request MAC verifies for matching transcript")
    func requestMACRoundTrip() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x11, count: OTA.nonceSize)
        let proof = AuthProof.computeRequestMAC(
            psk: key,
            mode: "auth",
            nonce: nonce,
            reason: "sudo",
            hostname: "client.local",
            hasStoredKey: true
        ).base64EncodedString()

        #expect(AuthProof.verifyRequestMAC(
            proofBase64: proof,
            psk: key,
            mode: "auth",
            nonce: nonce,
            reason: "sudo",
            hostname: "client.local",
            hasStoredKey: true
        ))
    }

    @Test("request MAC rejects tampered reason/mode")
    func requestMACRejectsTamper() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0x22, count: OTA.nonceSize)
        let proof = AuthProof.computeRequestMAC(
            psk: key,
            mode: "auth",
            nonce: nonce,
            reason: "sudo",
            hostname: "client.local",
            hasStoredKey: false
        ).base64EncodedString()

        #expect(AuthProof.verifyRequestMAC(
            proofBase64: proof,
            psk: key,
            mode: "test",
            nonce: nonce,
            reason: "sudo",
            hostname: "client.local",
            hasStoredKey: false
        ) == false)
        #expect(AuthProof.verifyRequestMAC(
            proofBase64: proof,
            psk: key,
            mode: "auth",
            nonce: nonce,
            reason: "other",
            hostname: "client.local",
            hasStoredKey: false
        ) == false)
    }

    @Test("response MAC verifies and is channel-bound to cert fingerprint")
    func responseMACRoundTrip() {
        let key = SymmetricKey(size: .bits256)
        let nonceC = Data(repeating: 0x33, count: OTA.nonceSize)
        let nonceS = Data(repeating: 0x44, count: OTA.nonceSize)
        let certFP = Data(repeating: 0x55, count: 32)
        let signature = Data(repeating: 0xAA, count: 64)
        let proof = AuthProof.computeResponseMAC(
            psk: key,
            mode: "auth",
            nonceC: nonceC,
            nonceS: nonceS,
            approved: true,
            signature: signature,
            error: nil,
            certFingerprint: certFP
        ).base64EncodedString()

        #expect(AuthProof.verifyResponseMAC(
            proofBase64: proof,
            psk: key,
            mode: "auth",
            nonceC: nonceC,
            nonceS: nonceS,
            approved: true,
            signature: signature,
            error: nil,
            certFingerprint: certFP
        ))

        let otherCertFP = Data(repeating: 0x56, count: 32)
        #expect(AuthProof.verifyResponseMAC(
            proofBase64: proof,
            psk: key,
            mode: "auth",
            nonceC: nonceC,
            nonceS: nonceS,
            approved: true,
            signature: signature,
            error: nil,
            certFingerprint: otherCertFP
        ) == false)
    }

    @Test("signature payload changes when reason changes")
    func signaturePayloadIncludesReason() {
        let nonceC = Data(repeating: 0x11, count: OTA.nonceSize)
        let nonceS = Data(repeating: 0x22, count: OTA.nonceSize)
        let certFP = Data(repeating: 0x33, count: 32)
        let a = AuthProof.authSignaturePayload(
            nonceC: nonceC,
            nonceS: nonceS,
            approved: true,
            reason: "sudo",
            certFingerprint: certFP
        )
        let b = AuthProof.authSignaturePayload(
            nonceC: nonceC,
            nonceS: nonceS,
            approved: true,
            reason: "login",
            certFingerprint: certFP
        )
        #expect(a != b)
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
