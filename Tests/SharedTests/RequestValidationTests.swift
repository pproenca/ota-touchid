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
        mode: String? = nil,
        includePublicKey: Bool = false
    ) throws -> Data {
        let key = psk ?? self.psk
        let normalizedMode = mode ?? "auth"
        let proof = AuthProof.computeRequestMAC(
            psk: key,
            mode: normalizedMode,
            nonce: nonce,
            reason: reason,
            hostname: ProcessInfo.processInfo.hostName,
            hasStoredKey: hasStoredKey
        )
        let req = AuthRequest(
            mode: normalizedMode,
            nonce: nonce,
            reason: reason,
            hasStoredKey: hasStoredKey,
            requestMAC: proof,
            clientSignature: Data(repeating: 0x11, count: 64),
            clientPublicKey: includePublicKey ? Data(repeating: 0x22, count: 65) : nil
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

        if case .auth(let n, _, _, _, _, let src) = result {
            #expect(n == nonce)
            #expect(src == "10.0.0.1:5000")
        } else {
            Issue.record("Expected .auth, got \(result)")
        }
    }

    @Test("valid test request returns .test")
    func validTestRequest() throws {
        let nonce = Data(repeating: 0xAB, count: OTA.nonceSize)
        let payload = try makePayload(nonce: nonce, mode: "test")
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "10.0.0.1:5000")

        if case .test(let validatedNonce, _, let src) = result {
            #expect(validatedNonce == nonce)
            #expect(src == "10.0.0.1:5000")
        } else {
            Issue.record("Expected .test, got \(result)")
        }
    }

    @Test("valid enroll request returns .enroll")
    func validEnrollRequest() throws {
        let nonce = Data(repeating: 0xAB, count: OTA.nonceSize)
        let payload = try makePayload(
            nonce: nonce,
            reason: "enroll",
            mode: "enroll",
            includePublicKey: true
        )
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "10.0.0.1:5000")

        if case .enroll(let validatedNonce, _, let key, let sig, let src) = result {
            #expect(validatedNonce == nonce)
            #expect(key.count == 65)
            #expect(sig.count == 64)
            #expect(src == "10.0.0.1:5000")
        } else {
            Issue.record("Expected .enroll, got \(result)")
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
        let proof = AuthProof.computeRequestMAC(
            psk: psk,
            mode: "auth",
            nonce: shortNonce,
            reason: "test",
            hostname: ProcessInfo.processInfo.hostName,
            hasStoredKey: false
        )
        let req = AuthRequest(mode: "auth", nonce: shortNonce, reason: "test", requestMAC: proof)
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
        let req = AuthRequest(mode: "auth", nonce: nonce, reason: "test")
        let frame = try Frame.encode(req)
        let payload = Data(frame.suffix(from: 4))
        let limiter = SourceRateLimiter()

        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "x")
        }
    }

    @Test("client public key is preserved for auth requests")
    func authPublicKeyPreserved() throws {
        let payload = try makePayload(hasStoredKey: true, includePublicKey: true)
        let limiter = SourceRateLimiter()
        let result = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "x")

        if case .auth(_, _, _, let clientPublicKey, _, _) = result {
            #expect(clientPublicKey?.count == 65)
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
