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
}
