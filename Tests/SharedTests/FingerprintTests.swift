import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Key fingerprint")
struct FingerprintTests {
    @Test("produces colon-separated hex of correct length")
    func format() {
        let data = Data(repeating: 0xAB, count: 65)
        let fp = keyFingerprint(data)
        // 16 bytes × 2 hex chars + 15 colons = 47 characters
        #expect(fp.count == 47)
        #expect(fp.contains(":"))
        #expect(!fp.contains(" "))
    }

    @Test("deterministic for same input")
    func deterministic() {
        let data = Data(repeating: 0x42, count: 65)
        #expect(keyFingerprint(data) == keyFingerprint(data))
    }

    @Test("different keys produce different fingerprints")
    func uniqueness() {
        let k1 = P256.Signing.PrivateKey().publicKey.rawRepresentation
        let k2 = P256.Signing.PrivateKey().publicKey.rawRepresentation
        #expect(keyFingerprint(k1) != keyFingerprint(k2))
    }

    @Test("all hex characters are lowercase")
    func lowercaseHex() {
        let data = Data(repeating: 0xFF, count: 32)
        let fp = keyFingerprint(data)
        #expect(fp == fp.lowercased())
    }
}
