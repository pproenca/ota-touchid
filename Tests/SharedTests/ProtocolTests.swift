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
    @Test("Client descriptions do not leak internals")
    func clientDescriptions() {
        let internalError = OTAError.secureEnclaveUnavailable
        #expect(internalError.clientDescription == "Internal server error")
        #expect(internalError.errorDescription != internalError.clientDescription)

        let keyError = OTAError.keyGenerationFailed("SecRandom failed")
        #expect(keyError.clientDescription == "Internal server error")

        let authError = OTAError.authenticationFailed
        #expect(authError.clientDescription == "Authentication failed")
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
