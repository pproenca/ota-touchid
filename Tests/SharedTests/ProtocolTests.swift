import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Frame encoding/decoding")
struct FrameTests {
    @Test("Round-trip encode/decode preserves AuthRequest")
    func roundTripAuthRequest() throws {
        let nonce = Data(repeating: 0xAB, count: OTA.nonceSize)
        let original = AuthRequest(nonce: nonce, reason: "test")
        let encoded = try Frame.encode(original)

        // First 4 bytes are big-endian length
        let length = try Frame.readLength(from: encoded.prefix(4))
        #expect(length == encoded.count - 4)

        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthRequest.self, from: Data(payload))
        #expect(decoded.reason == "test")
        #expect(Data(base64Encoded: decoded.nonce) == nonce)
        #expect(decoded.version == OTA.protocolVersion)
        #expect(decoded.hasStoredKey == false)
        #expect(decoded.clientProof == nil)
        #expect(decoded.mode == nil)
    }

    @Test("Round-trip AuthRequest with all fields")
    func roundTripAuthRequestFull() throws {
        let nonce = Data(repeating: 0xAB, count: OTA.nonceSize)
        let proof = Data(repeating: 0x01, count: 32)
        let original = AuthRequest(
            nonce: nonce, reason: "sudo", hasStoredKey: true, clientProof: proof)
        let encoded = try Frame.encode(original)
        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthRequest.self, from: Data(payload))

        #expect(decoded.hasStoredKey == true)
        #expect(decoded.clientProof != nil)
        #expect(Data(base64Encoded: decoded.clientProof!) == proof)
        #expect(decoded.version == OTA.protocolVersion)
        #expect(decoded.mode == nil)
    }

    @Test("Round-trip encode/decode preserves AuthResponse")
    func roundTripAuthResponse() throws {
        let sig = Data(repeating: 0xCD, count: 64)
        let pub = Data(repeating: 0xEF, count: 65)
        let original = AuthResponse(approved: true, signature: sig, publicKey: pub)
        let encoded = try Frame.encode(original)

        let length = try Frame.readLength(from: encoded.prefix(4))
        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(payload))

        #expect(decoded.approved == true)
        #expect(Data(base64Encoded: decoded.signature!) == sig)
        #expect(Data(base64Encoded: decoded.publicKey!) == pub)
        #expect(decoded.testProof == nil)
        #expect(decoded.version == OTA.protocolVersion)
        #expect(length == payload.count)
    }

    @Test("readLength rejects oversized frames")
    func rejectOversizedFrame() {
        var header = Data(count: 4)
        let huge = UInt32(OTA.maxFrameSize + 1).bigEndian
        header.withUnsafeMutableBytes { $0.storeBytes(of: huge, as: UInt32.self) }

        #expect(throws: OTAError.self) {
            try Frame.readLength(from: header)
        }
    }

    @Test("readLength rejects zero-length frames")
    func rejectZeroLength() {
        let header = Data(repeating: 0, count: 4)
        #expect(throws: OTAError.self) {
            try Frame.readLength(from: header)
        }
    }

    @Test("readLength rejects short header")
    func rejectShortHeader() {
        let header = Data([0x00, 0x01])
        #expect(throws: OTAError.self) {
            try Frame.readLength(from: header)
        }
    }

    @Test("Denied response round-trips correctly")
    func deniedResponse() throws {
        let original = AuthResponse(approved: false, error: "biometry cancelled")
        let encoded = try Frame.encode(original)
        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(payload))

        #expect(decoded.approved == false)
        #expect(decoded.signature == nil)
        #expect(decoded.publicKey == nil)
        #expect(decoded.testProof == nil)
        #expect(decoded.error == "biometry cancelled")
        #expect(decoded.version == OTA.protocolVersion)
    }

    @Test("Response without public key when client has stored key")
    func responseWithoutPublicKey() throws {
        let sig = Data(repeating: 0xCD, count: 64)
        let original = AuthResponse(approved: true, signature: sig)
        let encoded = try Frame.encode(original)
        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthResponse.self, from: Data(payload))

        #expect(decoded.approved == true)
        #expect(decoded.publicKey == nil)
        #expect(decoded.signature != nil)
        #expect(decoded.testProof == nil)
    }

    @Test("Round-trip AuthRequest with test mode")
    func roundTripTestMode() throws {
        let nonce = Data(repeating: 0xCC, count: OTA.nonceSize)
        let proof = Data(repeating: 0x02, count: 32)
        let original = AuthRequest(
            nonce: nonce, reason: "test", hasStoredKey: true, clientProof: proof, mode: "test")
        let encoded = try Frame.encode(original)
        let payload = encoded.suffix(from: 4)
        let decoded = try Frame.decode(AuthRequest.self, from: Data(payload))

        #expect(decoded.mode == "test")
        #expect(decoded.reason == "test")
        #expect(decoded.hasStoredKey == true)
        #expect(decoded.clientProof != nil)
    }

    @Test("Backward compat: decode JSON without mode key yields nil")
    func backwardCompatMissingMode() throws {
        // Simulate a v1 client that doesn't send mode
        let json = """
        {"version":1,"nonce":"AAAA","reason":"sudo","hostname":"test","hasStoredKey":false}
        """
        let decoded = try JSONDecoder().decode(AuthRequest.self, from: json.data(using: .utf8)!)
        #expect(decoded.mode == nil)
        #expect(decoded.reason == "sudo")
    }

    @Test("readLength accepts exactly maxFrameSize")
    func acceptExactlyMaxFrame() throws {
        var header = Data(count: 4)
        let max = UInt32(OTA.maxFrameSize).bigEndian
        header.withUnsafeMutableBytes { $0.storeBytes(of: max, as: UInt32.self) }
        let length = try Frame.readLength(from: header)
        #expect(length == OTA.maxFrameSize)
    }

    @Test("readLength accepts minimum frame size of 1")
    func acceptMinimumFrame() throws {
        var header = Data(count: 4)
        let one = UInt32(1).bigEndian
        header.withUnsafeMutableBytes { $0.storeBytes(of: one, as: UInt32.self) }
        let length = try Frame.readLength(from: header)
        #expect(length == 1)
    }

    @Test("readLength rejects maxFrameSize + 1")
    func rejectOneOverMax() {
        var header = Data(count: 4)
        let over = UInt32(OTA.maxFrameSize + 1).bigEndian
        header.withUnsafeMutableBytes { $0.storeBytes(of: over, as: UInt32.self) }
        #expect(throws: OTAError.self) {
            try Frame.readLength(from: header)
        }
    }

    @Test("encode/readLength round-trip for AuthRequest")
    func encodeLengthRoundTrip() throws {
        let nonce = Data(repeating: 0xFF, count: OTA.nonceSize)
        let req = AuthRequest(nonce: nonce, reason: "test")
        let encoded = try Frame.encode(req)
        let length = try Frame.readLength(from: Data(encoded.prefix(4)))
        #expect(length == encoded.count - 4)
    }

    @Test("decode rejects garbage JSON")
    func decodeRejectsGarbage() {
        let garbage = Data("this is not json".utf8)
        #expect(throws: (any Error).self) {
            try Frame.decode(AuthRequest.self, from: garbage)
        }
    }

    @Test("decode rejects empty payload")
    func decodeRejectsEmpty() {
        #expect(throws: (any Error).self) {
            try Frame.decode(AuthRequest.self, from: Data())
        }
    }
}

@Suite("OTA constants")
struct ConstantsTests {
    @Test("Nonce size is 32 bytes")
    func nonceSize() {
        #expect(OTA.nonceSize == 32)
    }

    @Test("Config dir is under ~/.config/ota-touchid")
    func configDir() {
        let path = OTA.configDir.path
        #expect(path.hasSuffix(".config/ota-touchid"))
    }

    @Test("Protocol version is set")
    func protocolVersion() {
        #expect(OTA.protocolVersion >= 1)
    }

    @Test("PSK file is under config dir")
    func pskFile() {
        let path = OTA.pskFile.path
        #expect(path.hasSuffix(".config/ota-touchid/psk"))
    }
}

@Suite("Error descriptions")
struct ErrorTests {
    @Test("every error has a non-empty errorDescription")
    func allErrorDescriptions() {
        let errors: [OTAError] = [
            .secureEnclaveUnavailable,
            .keyGenerationFailed("test"),
            .badRequest("test"),
            .serverNotFound,
            .shortRead,
            .timeout,
            .frameTooLarge(999),
            .signatureVerificationFailed,
            .testProofVerificationFailed,
            .serverKeyNotTrusted,
            .invalidPort("abc"),
            .authenticationFailed,
        ]
        for error in errors {
            #expect(error.errorDescription != nil, "Missing errorDescription for \(error)")
            #expect(!error.errorDescription!.isEmpty, "Empty errorDescription for \(error)")
        }
    }

    @Test("client descriptions never leak internal details")
    func clientDescriptionsDoNotLeak() {
        // Internal errors → "Internal server error"
        #expect(OTAError.secureEnclaveUnavailable.clientDescription == "Internal server error")
        #expect(OTAError.keyGenerationFailed("SecRandom failed").clientDescription == "Internal server error")

        // Client errors → specific safe messages
        #expect(OTAError.badRequest("invalid nonce").clientDescription == "Bad request")
        #expect(OTAError.frameTooLarge(999_999).clientDescription == "Request too large")
        #expect(OTAError.authenticationFailed.clientDescription == "Authentication failed")

        // Everything else → "Request denied"
        #expect(OTAError.serverNotFound.clientDescription == "Request denied")
        #expect(OTAError.shortRead.clientDescription == "Request denied")
        #expect(OTAError.timeout.clientDescription == "Request denied")
        #expect(OTAError.signatureVerificationFailed.clientDescription == "Request denied")
        #expect(OTAError.testProofVerificationFailed.clientDescription == "Request denied")
        #expect(OTAError.serverKeyNotTrusted.clientDescription == "Request denied")
        #expect(OTAError.invalidPort("abc").clientDescription == "Request denied")
    }

    @Test("internal detail never appears in clientDescription")
    func noInternalLeaks() {
        let error = OTAError.keyGenerationFailed("SecRandomCopyBytes returned -25300")
        #expect(!error.clientDescription.contains("SecRandom"))
        #expect(!error.clientDescription.contains("-25300"))

        let badReq = OTAError.badRequest("nonce too short: got 16 expected 32")
        #expect(!badReq.clientDescription.contains("nonce"))
        #expect(!badReq.clientDescription.contains("16"))
    }
}

@Suite("Message construction")
struct MessageTests {
    @Test("AuthRequest encodes nonce as base64 and sets version")
    func authRequestInit() {
        let nonce = Data([0x01, 0x02, 0x03])
        let req = AuthRequest(nonce: nonce, reason: "sudo")
        #expect(req.version == OTA.protocolVersion)
        #expect(req.nonce == nonce.base64EncodedString())
        #expect(req.reason == "sudo")
        #expect(req.hostname == ProcessInfo.processInfo.hostName)
        #expect(req.hasStoredKey == false)
        #expect(req.clientProof == nil)
        #expect(req.mode == nil)
    }

    @Test("AuthRequest with all optional fields")
    func authRequestFull() {
        let nonce = Data(repeating: 0xAA, count: 32)
        let proof = Data(repeating: 0xBB, count: 32)
        let req = AuthRequest(nonce: nonce, reason: "test", hasStoredKey: true, clientProof: proof, mode: "test")
        #expect(req.hasStoredKey == true)
        #expect(req.clientProof == proof.base64EncodedString())
        #expect(req.mode == "test")
    }

    @Test("AuthResponse encodes signature and publicKey as base64")
    func authResponseInit() {
        let sig = Data(repeating: 0xCD, count: 64)
        let pub = Data(repeating: 0xEF, count: 65)
        let resp = AuthResponse(approved: true, signature: sig, publicKey: pub)
        #expect(resp.version == OTA.protocolVersion)
        #expect(resp.approved == true)
        #expect(resp.signature == sig.base64EncodedString())
        #expect(resp.publicKey == pub.base64EncodedString())
        #expect(resp.testProof == nil)
        #expect(resp.error == nil)
    }

    @Test("AuthResponse denied with error, no signature")
    func authResponseDenied() {
        let resp = AuthResponse(approved: false, error: "denied by user")
        #expect(resp.approved == false)
        #expect(resp.signature == nil)
        #expect(resp.publicKey == nil)
        #expect(resp.testProof == nil)
        #expect(resp.error == "denied by user")
    }

    @Test("AuthResponse minimal approved, no optional fields")
    func authResponseMinimal() {
        let resp = AuthResponse(approved: true)
        #expect(resp.approved == true)
        #expect(resp.signature == nil)
        #expect(resp.publicKey == nil)
        #expect(resp.testProof == nil)
        #expect(resp.error == nil)
    }
}

@Suite("PSK proof verification")
struct PSKTests {
    @Test("HMAC-SHA256 proof is deterministic for same inputs")
    func hmacDeterministic() {
        let key = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0xAA, count: 32)
        let mac1 = Data(HMAC<SHA256>.authenticationCode(for: nonce, using: key))
        let mac2 = Data(HMAC<SHA256>.authenticationCode(for: nonce, using: key))
        #expect(mac1 == mac2)
    }

    @Test("Different nonces produce different proofs")
    func hmacDiffersForDifferentNonces() {
        let key = SymmetricKey(size: .bits256)
        let nonce1 = Data(repeating: 0xAA, count: 32)
        let nonce2 = Data(repeating: 0xBB, count: 32)
        let mac1 = Data(HMAC<SHA256>.authenticationCode(for: nonce1, using: key))
        let mac2 = Data(HMAC<SHA256>.authenticationCode(for: nonce2, using: key))
        #expect(mac1 != mac2)
    }

    @Test("Different keys produce different proofs")
    func hmacDiffersForDifferentKeys() {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let nonce = Data(repeating: 0xAA, count: 32)
        let mac1 = Data(HMAC<SHA256>.authenticationCode(for: nonce, using: key1))
        let mac2 = Data(HMAC<SHA256>.authenticationCode(for: nonce, using: key2))
        #expect(mac1 != mac2)
    }
}
