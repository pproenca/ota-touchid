import CryptoKit
import Foundation
import Network
import Security

// MARK: - TLS Peer Info (for channel binding) [M2]

/// Captures the peer's TLS certificate fingerprint during the handshake.
/// Used for channel binding: the signature covers nonce || certFingerprint,
/// so a MITM with a different TLS certificate causes verification failure.
public final class TLSPeerInfo: @unchecked Sendable {
    public private(set) var certFingerprint: Data?
    public init() {}

    fileprivate func set(_ fingerprint: Data) {
        self.certFingerprint = fingerprint
    }
}

// MARK: - TLS Parameters

public enum TLSConfig {
    /// Server-side TLS parameters with an ephemeral self-signed identity.
    /// Returns parameters and the SHA-256 fingerprint of the TLS certificate
    /// for use in channel binding.
    public static func serverParameters() throws -> (params: NWParameters, certFingerprint: Data) {
        let (identity, certDER) = try createEphemeralIdentity()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
        let fingerprint = Data(SHA256.hash(data: certDER))
        return (NWParameters(tls: tls), fingerprint)
    }

    /// Client-side TLS parameters.
    /// Certificate verification is skipped — authentication is done via our
    /// nonce/signature layer with channel binding, not the TLS certificate chain.
    /// The peer's certificate fingerprint is captured into `peerInfo` for channel binding.
    public static func clientParameters(peerInfo: TLSPeerInfo) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(
            tls.securityProtocolOptions,
            { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                if let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                    let leaf = chain.first
                {
                    let certData = SecCertificateCopyData(leaf) as Data
                    peerInfo.set(Data(SHA256.hash(data: certData)))
                }
                complete(true)
            },
            .main
        )
        return NWParameters(tls: tls)
    }
}

// MARK: - Ephemeral Identity

private let keychainLabel = "com.ota-touchid.tls-ephemeral"
private let certCN = "OTA Touch ID"

/// Creates an ephemeral TLS identity and returns it along with the raw DER certificate.
private func createEphemeralIdentity() throws -> (sec_identity_t, Data) {
    // Clean up previous run's artifacts.
    // Note: Keychain auto-sets certificate labels to the Subject CN, not our custom label.
    for cls in [kSecClassKey, kSecClassIdentity] {
        SecItemDelete([kSecClass: cls, kSecAttrLabel: keychainLabel] as CFDictionary)
    }
    SecItemDelete([kSecClass: kSecClassCertificate, kSecAttrLabel: certCN] as CFDictionary)

    // 1. Generate ephemeral P-256 key pair in the Keychain
    let keyTag = keychainLabel.data(using: .utf8)!
    let keyAttrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrApplicationTag as String: keyTag,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrLabel as String: keychainLabel,
        ] as [String: Any],
    ]

    var cfError: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfError) else {
        throw cfError!.takeRetainedValue()
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey),
        let pubData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
    else {
        throw OTAError.keyGenerationFailed("cannot export public key")
    }

    // 2. Build a minimal self-signed X.509 certificate (DER)
    let certDER = try SelfSignedCert.build(publicKeyX963: pubData, signWith: privateKey)

    guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
        throw OTAError.keyGenerationFailed("invalid certificate DER")
    }

    // 3. Add certificate to keychain so the system can link it to the private key
    let addStatus = SecItemAdd(
        [
            kSecClass: kSecClassCertificate,
            kSecValueRef: cert,
            kSecAttrLabel: keychainLabel,
        ] as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
        throw OTAError.keyGenerationFailed("keychain cert add failed: \(addStatus)")
    }

    // 4. Query for the linked identity (cert + private key)
    var ref: CFTypeRef?
    let idStatus = SecItemCopyMatching(
        [
            kSecClass: kSecClassIdentity,
            kSecAttrApplicationTag: keyTag,
            kSecReturnRef: true,
        ] as CFDictionary, &ref)
    guard idStatus == errSecSuccess else {
        throw OTAError.keyGenerationFailed("identity lookup failed: \(idStatus)")
    }

    // swiftlint:disable:next force_cast
    let secIdentity = ref as! SecIdentity
    guard let wrapped = sec_identity_create(secIdentity) else {
        throw OTAError.keyGenerationFailed("sec_identity_create returned nil")
    }
    return (wrapped, certDER)
}

// MARK: - Minimal DER X.509 Certificate Builder

private enum SelfSignedCert {
    static func build(publicKeyX963: Data, signWith key: SecKey) throws -> Data {
        let tbs = tbsCertificate(publicKeyX963: [UInt8](publicKeyX963))
        let tbsData = Data(DER.sequence(tbs))

        var cfError: Unmanaged<CFError>?
        guard
            let sig = SecKeyCreateSignature(
                key, .ecdsaSignatureMessageX962SHA256, tbsData as CFData, &cfError
            ) as Data?
        else {
            throw cfError!.takeRetainedValue()
        }

        let full = DER.sequence(
            [UInt8](tbsData)
                + ecdsaSHA256OID
                + DER.bitString([UInt8](sig))
        )
        return Data(full)
    }

    // -- TBS (To-Be-Signed) Certificate --

    private static func tbsCertificate(publicKeyX963: [UInt8]) -> [UInt8] {
        let serial = DER.integer([0x01])
        let issuer = rdnSequence("OTA Touch ID")
        let validity = DER.sequence(
            DER.utcTime("250101000000Z") + DER.utcTime("350101000000Z")
        )
        let spki = DER.sequence(
            DER.sequence(
                DER.oid(OID.ecPublicKey) + DER.oid(OID.prime256v1)
            ) + DER.bitString(publicKeyX963)
        )
        return serial + ecdsaSHA256OID + issuer + validity + issuer + spki
    }

    private static func rdnSequence(_ cn: String) -> [UInt8] {
        DER.sequence(
            DER.set(
                DER.sequence(DER.oid(OID.commonName) + DER.utf8String(cn))
            ))
    }

    private static let ecdsaSHA256OID: [UInt8] = DER.sequence(
        DER.oid(OID.ecdsaWithSHA256)
    )
}

// MARK: - ASN.1 DER Encoding

private enum DER {
    static func sequence(_ c: [UInt8]) -> [UInt8] { tlv(0x30, c) }
    static func set(_ c: [UInt8]) -> [UInt8] { tlv(0x31, c) }
    static func integer(_ b: [UInt8]) -> [UInt8] { tlv(0x02, b) }
    static func bitString(_ b: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + b) }
    static func oid(_ b: [UInt8]) -> [UInt8] { tlv(0x06, b) }
    static func utf8String(_ s: String) -> [UInt8] { tlv(0x0C, [UInt8](s.utf8)) }
    static func utcTime(_ s: String) -> [UInt8] { tlv(0x17, [UInt8](s.utf8)) }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let n = content.count
        precondition(n <= 0xFFFF, "DER content too large: \(n) bytes (max 65535)")
        var out: [UInt8] = [tag]
        if n < 0x80 {
            out.append(UInt8(n))
        } else if n < 0x100 {
            out.append(contentsOf: [0x81, UInt8(n)])
        } else {
            out.append(contentsOf: [0x82, UInt8(n >> 8), UInt8(n & 0xFF)])
        }
        out.append(contentsOf: content)
        return out
    }
}

// MARK: - Well-known OIDs (encoded)

private enum OID {
    static let commonName: [UInt8] = [0x55, 0x04, 0x03]
    static let ecPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    static let prime256v1: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    static let ecdsaWithSHA256: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
}
