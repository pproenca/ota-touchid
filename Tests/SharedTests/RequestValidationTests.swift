import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Request validation")
struct RequestValidationTests {
    let psk = SymmetricKey(size: .bits256)

    private func makePayload(
        nonce: Data = Data(repeating: 0xAA, count: OTA.nonceSize),
        reason: String = "test",
        hasStoredKey: Bool = false,
        psk: SymmetricKey? = nil,
        mode: String? = nil
    ) throws -> Data {
        let key = psk ?? self.psk
        let proof = AuthProof.compute(psk: key, nonce: nonce)
        let req = AuthRequest(
            nonce: nonce,
            reason: reason,
            hasStoredKey: hasStoredKey,
            clientProof: proof,
            mode: mode
        )
        let frame = try Frame.encode(req)
        return Data(frame.suffix(from: 4))
    }

    @Test("valid auth request returns .auth")
    func validAuthRequest() throws {
        let nonce = Data(repeating: 0xAA, count: OTA.nonceSize)
        let payload = try makePayload(nonce: nonce)
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "10.0.0.1:5000")

        if case .auth(let n, _, let hasKey, let src) = result {
            #expect(n == nonce)
            #expect(hasKey == false)
            #expect(src == "10.0.0.1:5000")
        } else {
            Issue.record("Expected .auth, got \(result)")
        }
    }

    @Test("valid test request returns .test")
    func validTestRequest() throws {
        let payload = try makePayload(mode: "test")
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "10.0.0.1:5000")

        if case .test(_, let src) = result {
            #expect(src == "10.0.0.1:5000")
        } else {
            Issue.record("Expected .test, got \(result)")
        }
    }

    @Test("rejects when rate limited")
    func rejectsWhenRateLimited() throws {
        let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 60) { Date() }
        let payload = try makePayload()

        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "attacker")

        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "attacker")
        }
    }

    @Test("rejects garbage payload")
    func rejectsGarbage() {
        let limiter = SourceRateLimiter()
        #expect(throws: (any Error).self) {
            try validateAuthRequest(payload: Data("not json".utf8), psk: self.psk, rateLimiter: limiter, source: "x")
        }
    }

    @Test("rejects invalid nonce (wrong size)")
    func rejectsShortNonce() throws {
        let shortNonce = Data(repeating: 0xAA, count: 16)
        let proof = AuthProof.compute(psk: psk, nonce: shortNonce)
        let req = AuthRequest(nonce: shortNonce, reason: "test", clientProof: proof)
        let frame = try Frame.encode(req)
        let payload = Data(frame.suffix(from: 4))
        let limiter = SourceRateLimiter()

        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "x")
        }
    }

    @Test("rejects wrong PSK proof")
    func rejectsWrongPSK() throws {
        let wrongKey = SymmetricKey(size: .bits256)
        let payload = try makePayload(psk: wrongKey)
        let limiter = SourceRateLimiter()

        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "x")
        }
    }

    @Test("rejects request with nil proof")
    func rejectsNilProof() throws {
        let nonce = Data(repeating: 0xAA, count: OTA.nonceSize)
        let req = AuthRequest(nonce: nonce, reason: "test")
        let frame = try Frame.encode(req)
        let payload = Data(frame.suffix(from: 4))
        let limiter = SourceRateLimiter()

        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "x")
        }
    }

    @Test("hasStoredKey is preserved in validated result")
    func hasStoredKeyPreserved() throws {
        let payload = try makePayload(hasStoredKey: true)
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "x")

        if case .auth(_, _, let hasKey, _) = result {
            #expect(hasKey == true)
        } else {
            Issue.record("Expected .auth")
        }
    }

    @Test("different sources have independent rate limits")
    func independentRateLimits() throws {
        let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 60) { Date() }
        let payload = try makePayload()

        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "A")
        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "A")
        }

        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "B")
    }
}
