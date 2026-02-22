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
        let reason = "sudo"
        let requestMAC = AuthProof.computeRequestMAC(
            psk: psk,
            mode: "auth",
            nonce: nonce,
            reason: reason,
            hostname: ProcessInfo.processInfo.hostName,
            hasStoredKey: false
        )
        let request = AuthRequest(
            mode: "auth",
            nonce: nonce,
            reason: reason,
            hasStoredKey: false,
            requestMAC: requestMAC
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

        guard case .auth(let validatedNonce, let validatedReason, _, let hasStoredKey, _) = validated else {
            Issue.record("Expected .auth variant")
            return
        }
        #expect(validatedNonce == nonce)
        #expect(validatedReason == reason)
        #expect(hasStoredKey == false)

        // === Server side: build response (simulating approval) ===
        let certFP = Data(repeating: 0xAB, count: 32)
        let nonceS = Data(repeating: 0xBC, count: OTA.nonceSize)
        let fakeSignature = Data(repeating: 0xCD, count: 64)
        let fakePublicKey = Data(repeating: 0xEF, count: 65)
        let responseMAC = AuthProof.computeResponseMAC(
            psk: psk,
            mode: "auth",
            nonceC: nonce,
            nonceS: nonceS,
            approved: true,
            signature: fakeSignature,
            error: nil,
            certFingerprint: certFP
        )
        let response = AuthResponse(
            mode: "auth",
            approved: true,
            nonceS: nonceS,
            signature: fakeSignature,
            publicKey: fakePublicKey,
            responseMAC: responseMAC
        )
        let responseFrame = try Frame.encode(response)

        // === Client side: decode response ===
        let responseLength = try Frame.readLength(from: Data(responseFrame.prefix(4)))
        let responsePayload = Data(responseFrame.suffix(from: 4))
        #expect(responsePayload.count == responseLength)

        let decoded = try Frame.decode(AuthResponse.self, from: responsePayload)
        #expect(decoded.approved == true)
        #expect(decoded.nonceS == nonceS.base64EncodedString())
        #expect(Data(base64Encoded: decoded.signature!) == fakeSignature)
        #expect(Data(base64Encoded: decoded.publicKey!) == fakePublicKey)
        #expect(decoded.responseMAC != nil)
    }

    @Test("test mode round-trip")
    func testModeRoundTrip() throws {
        let nonce = Data(repeating: 0xBB, count: OTA.nonceSize)
        let certFP = Data(repeating: 0xCC, count: 32)
        let nonceS = Data(repeating: 0xDD, count: OTA.nonceSize)
        let requestMAC = AuthProof.computeRequestMAC(
            psk: psk,
            mode: "test",
            nonce: nonce,
            reason: "connectivity-test",
            hostname: ProcessInfo.processInfo.hostName,
            hasStoredKey: true
        )
        let request = AuthRequest(
            mode: "test",
            nonce: nonce,
            reason: "connectivity-test",
            hasStoredKey: true,
            requestMAC: requestMAC
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

        guard case .test(let validatedNonce, _, let source) = validated else {
            Issue.record("Expected .test variant")
            return
        }
        #expect(validatedNonce == nonce)
        #expect(source == "10.0.0.2:9999")

        let responseMAC = AuthProof.computeResponseMAC(
            psk: psk,
            mode: "test",
            nonceC: nonce,
            nonceS: nonceS,
            approved: true,
            signature: nil,
            error: nil,
            certFingerprint: certFP
        )
        let response = AuthResponse(
            mode: "test",
            approved: true,
            nonceS: nonceS,
            responseMAC: responseMAC
        )
        let responseFrame = try Frame.encode(response)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(responseFrame.suffix(from: 4)))
        #expect(decoded.approved == true)
        #expect(decoded.signature == nil)
        #expect(decoded.responseMAC != nil)
        #expect(AuthProof.verifyResponseMAC(
            proofBase64: decoded.responseMAC,
            psk: psk,
            mode: "test",
            nonceC: nonce,
            nonceS: nonceS,
            approved: true,
            signature: nil,
            error: nil,
            certFingerprint: certFP
        ))
    }

    @Test("denied response round-trip")
    func deniedRoundTrip() throws {
        let nonce = Data(repeating: 0xEA, count: OTA.nonceSize)
        let nonceS = Data(repeating: 0xFB, count: OTA.nonceSize)
        let certFP = Data(repeating: 0xCC, count: 32)
        let err = "Authentication denied"
        let responseMAC = AuthProof.computeResponseMAC(
            psk: psk,
            mode: "auth",
            nonceC: nonce,
            nonceS: nonceS,
            approved: false,
            signature: nil,
            error: err,
            certFingerprint: certFP
        )
        let response = AuthResponse(
            mode: "auth",
            approved: false,
            nonceS: nonceS,
            responseMAC: responseMAC,
            error: err
        )
        let frame = try Frame.encode(response)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(frame.suffix(from: 4)))
        #expect(decoded.approved == false)
        #expect(decoded.error == "Authentication denied")
        #expect(decoded.signature == nil)
        #expect(decoded.responseMAC != nil)
    }

    @Test("wrong PSK is caught during validation")
    func wrongPSKCaughtInPipeline() throws {
        let clientPSK = SymmetricKey(size: .bits256)
        let serverPSK = SymmetricKey(size: .bits256)  // different!

        let nonce = Data(repeating: 0xCC, count: OTA.nonceSize)
        let requestMAC = AuthProof.computeRequestMAC(
            psk: clientPSK,
            mode: "auth",
            nonce: nonce,
            reason: "sudo",
            hostname: ProcessInfo.processInfo.hostName,
            hasStoredKey: false
        )
        let request = AuthRequest(mode: "auth", nonce: nonce, reason: "sudo", requestMAC: requestMAC)
        let frame = try Frame.encode(request)
        let payload = Data(frame.suffix(from: 4))

        let limiter = SourceRateLimiter()
        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: serverPSK, rateLimiter: limiter, source: "x")
        }
    }
}
