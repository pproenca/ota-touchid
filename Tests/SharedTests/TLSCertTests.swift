import CryptoKit
import Foundation
import Security
import Testing

@testable import Shared

@Suite("TLS certificate generation")
struct TLSCertTests {
    @Test("self-signed DER fixture parses as SecCertificate")
    func selfSignedDERParses() {
        let key = P256.Signing.PrivateKey()
        let der = buildSelfSignedCertDERForTesting(publicKeyX963: key.publicKey.x963Representation)
        let cert = SecCertificateCreateWithData(nil, der as CFData)

        #expect(der.count > 0)
        #expect(cert != nil)
    }

    @Test("server parameters include a 32-byte certificate fingerprint", .enabled(if: SecureEnclave.isAvailable))
    func serverParametersHaveFingerprint() throws {
        let (_, fingerprint) = try TLSConfig.serverParameters()
        #expect(fingerprint.count == 32)
    }

    @Test("DER cert contains expected subject CN")
    func certContainsSubjectCN() {
        let key = P256.Signing.PrivateKey()
        let der = buildSelfSignedCertDERForTesting(publicKeyX963: key.publicKey.x963Representation)
        let cert = SecCertificateCreateWithData(nil, der as CFData)!
        let summary = SecCertificateCopySubjectSummary(cert) as String?
        #expect(summary == "OTA Touch ID")
    }

    @Test("different keys produce different certificates")
    func differentKeysProduceDifferentCerts() {
        let key1 = P256.Signing.PrivateKey()
        let key2 = P256.Signing.PrivateKey()
        let der1 = buildSelfSignedCertDERForTesting(publicKeyX963: key1.publicKey.x963Representation)
        let der2 = buildSelfSignedCertDERForTesting(publicKeyX963: key2.publicKey.x963Representation)
        #expect(der1 != der2)
    }

    @Test("cert DER has non-trivial size for P256")
    func certDERHasReasonableSize() {
        let key = P256.Signing.PrivateKey()
        let der = buildSelfSignedCertDERForTesting(publicKeyX963: key.publicKey.x963Representation)
        // A minimal self-signed P256 cert should be ~300-500 bytes
        #expect(der.count > 200)
        #expect(der.count < 1000)
    }

    @Test("TLSPeerInfo starts with nil fingerprint")
    func peerInfoStartsNil() {
        let info = TLSPeerInfo()
        #expect(info.certFingerprint == nil)
    }
}
