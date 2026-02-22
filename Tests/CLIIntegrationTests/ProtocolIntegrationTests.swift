import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Protocol integration")
struct ProtocolIntegrationTests {
    let psk = SymmetricKey(size: .bits256)

    @Test("full auth request/response round-trip at data level")
    func fullAuthRoundTrip() throws {
        // === Client side: build request ===
        let nonce = Data(repeating: 0xAA, count: OTA.nonceSize)
        let proof = AuthProof.compute(psk: psk, nonce: nonce)
        let request = AuthRequest(
            nonce: nonce,
            reason: "sudo",
            hasStoredKey: false,
            clientProof: proof
        )
        let requestFrame = try Frame.encode(request)

        // === Server side: validate request ===
        let requestLength = try Frame.readLength(from: Data(requestFrame.prefix(4)))
        let requestPayload = Data(requestFrame.suffix(from: 4))
        #expect(requestPayload.count == requestLength)

        let limiter = SourceRateLimiter()
        let validated = try validateAuthRequest(
            payload: requestPayload,
            psk: psk,
            rateLimiter: limiter,
            source: "10.0.0.1:12345"
        )

        guard case .auth(let validatedNonce, _, let hasStoredKey, _) = validated else {
            Issue.record("Expected .auth variant")
            return
        }
        #expect(validatedNonce == nonce)
        #expect(hasStoredKey == false)

        // === Server side: build response (simulating approval) ===
        let fakeSignature = Data(repeating: 0xCD, count: 64)
        let fakePublicKey = Data(repeating: 0xEF, count: 65)
        let response = AuthResponse(
            approved: true,
            signature: fakeSignature,
            publicKey: fakePublicKey
        )
        let responseFrame = try Frame.encode(response)

        // === Client side: decode response ===
        let responseLength = try Frame.readLength(from: Data(responseFrame.prefix(4)))
        let responsePayload = Data(responseFrame.suffix(from: 4))
        #expect(responsePayload.count == responseLength)

        let decoded = try Frame.decode(AuthResponse.self, from: responsePayload)
        #expect(decoded.approved == true)
        #expect(Data(base64Encoded: decoded.signature!) == fakeSignature)
        #expect(Data(base64Encoded: decoded.publicKey!) == fakePublicKey)
    }

    @Test("test mode round-trip")
    func testModeRoundTrip() throws {
        let nonce = Data(repeating: 0xBB, count: OTA.nonceSize)
        let proof = AuthProof.compute(psk: psk, nonce: nonce)
        let request = AuthRequest(
            nonce: nonce,
            reason: "test",
            hasStoredKey: true,
            clientProof: proof,
            mode: "test"
        )
        let requestFrame = try Frame.encode(request)

        let requestPayload = Data(requestFrame.suffix(from: 4))
        let limiter = SourceRateLimiter()
        let validated = try validateAuthRequest(
            payload: requestPayload,
            psk: psk,
            rateLimiter: limiter,
            source: "10.0.0.2:9999"
        )

        guard case .test(_, let source) = validated else {
            Issue.record("Expected .test variant")
            return
        }
        #expect(source == "10.0.0.2:9999")

        // Server responds with simple approval (no signature needed for test mode)
        let response = AuthResponse(approved: true)
        let responseFrame = try Frame.encode(response)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(responseFrame.suffix(from: 4)))
        #expect(decoded.approved == true)
        #expect(decoded.signature == nil)
    }

    @Test("denied response round-trip")
    func deniedRoundTrip() throws {
        let response = AuthResponse(approved: false, error: "Authentication denied")
        let frame = try Frame.encode(response)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(frame.suffix(from: 4)))
        #expect(decoded.approved == false)
        #expect(decoded.error == "Authentication denied")
        #expect(decoded.signature == nil)
    }

    @Test("wrong PSK is caught during validation")
    func wrongPSKCaughtInPipeline() throws {
        let clientPSK = SymmetricKey(size: .bits256)
        let serverPSK = SymmetricKey(size: .bits256)  // different!

        let nonce = Data(repeating: 0xCC, count: OTA.nonceSize)
        let proof = AuthProof.compute(psk: clientPSK, nonce: nonce)
        let request = AuthRequest(nonce: nonce, reason: "sudo", clientProof: proof)
        let frame = try Frame.encode(request)
        let payload = Data(frame.suffix(from: 4))

        let limiter = SourceRateLimiter()
        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: serverPSK, rateLimiter: limiter, source: "x")
        }
    }
}
