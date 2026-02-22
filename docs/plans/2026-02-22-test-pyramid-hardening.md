# Test Pyramid Hardening — OTA TouchID

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the embarrassing test coverage gaps that let regressions slip through by building a proper test pyramid from the bottom up.

**Architecture:** The codebase has ~2,100 lines of production code across 6 files, and only ~300 lines of tests covering the Shared module and some CLI smoke tests. Zero tests for ClientLib. Zero tests for ServerLib. The server's request handling pipeline — literally the security-critical path — is buried in a private class with no test seams. We fix this by (1) hardening existing unit tests for edge cases, (2) extracting testable logic from the server/client monoliths, (3) testing the extracted logic, and (4) adding integration tests at the protocol level.

**Tech Stack:** Swift 5.9+, Swift Testing framework, CryptoKit, macOS 14+

**Current state:** 28 tests pass. Build is green. But coverage is tissue-paper thin.

---

## Phase 1: Harden the Foundation (Unit Tests — Base of Pyramid)

These are pure-function tests. No file system, no network, no hardware. If we can't even get these right, everything above is a house of cards.

---

### Task 1: SourceRateLimiter Edge Cases

**Files:**
- Modify: `Tests/SharedTests/AuthPrimitivesTests.swift`

The existing test covers the happy path. It doesn't test exact boundary behavior, window reset edge, or zero-budget configs. The rate limiter is a security control — if it's wrong, we get brute-forced.

**Step 1: Write the failing tests**

Add these tests inside the existing `SourceRateLimiterTests` suite in `Tests/SharedTests/AuthPrimitivesTests.swift`:

```swift
@Test("allows exactly maxAttempts, blocks on maxAttempts+1")
func exactBudgetBoundary() {
    let limiter = SourceRateLimiter(maxAttempts: 3, windowSeconds: 60) { Date() }
    #expect(limiter.shouldAllow(source: "a"))  // 1
    #expect(limiter.shouldAllow(source: "a"))  // 2
    #expect(limiter.shouldAllow(source: "a"))  // 3
    #expect(limiter.shouldAllow(source: "a") == false)  // 4 = blocked
}

@Test("window reset allows a fresh budget")
func windowResetGivesFreshBudget() {
    var now = Date(timeIntervalSince1970: 1_000_000)
    let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 10) { now }

    #expect(limiter.shouldAllow(source: "x"))       // 1 — allowed
    #expect(limiter.shouldAllow(source: "x") == false)  // 2 — blocked

    // Advance exactly to the window boundary
    now = now.addingTimeInterval(10)
    #expect(limiter.shouldAllow(source: "x"))       // reset, allowed again
    #expect(limiter.shouldAllow(source: "x") == false)  // blocked again
}

@Test("sources are fully independent")
func sourcesAreIndependent() {
    let limiter = SourceRateLimiter(maxAttempts: 1, windowSeconds: 60) { Date() }

    #expect(limiter.shouldAllow(source: "a"))
    #expect(limiter.shouldAllow(source: "a") == false)

    // b is unaffected
    #expect(limiter.shouldAllow(source: "b"))
    #expect(limiter.shouldAllow(source: "b") == false)

    // c is unaffected
    #expect(limiter.shouldAllow(source: "c"))
}
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter SourceRateLimiter 2>&1 | tail -20`
Expected: All 4 tests PASS (these test existing behavior — they should pass if the code is correct)

**Step 3: Commit**

```bash
git add Tests/SharedTests/AuthPrimitivesTests.swift
git commit -m "test: add rate limiter edge case tests (exact boundary, window reset, source independence)"
```

---

### Task 2: OTAError Complete Coverage

**Files:**
- Modify: `Tests/SharedTests/ProtocolTests.swift`

Only 3 of 10 error variants are tested for `clientDescription`. The `default` case in the switch hides bugs — if someone adds a new error variant and forgets to add a client description, it silently falls through to "Request denied". Every variant must be explicitly tested.

**Step 1: Write the failing tests**

Replace the existing `ErrorTests` suite in `Tests/SharedTests/ProtocolTests.swift`:

```swift
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
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter ErrorTests 2>&1 | tail -20`
Expected: PASS (testing existing behavior)

**Step 3: Commit**

```bash
git add Tests/SharedTests/ProtocolTests.swift
git commit -m "test: exhaustive OTAError coverage — every variant, every client description, leak checks"
```

---

### Task 3: Frame Boundary Tests

**Files:**
- Modify: `Tests/SharedTests/ProtocolTests.swift`

The frame protocol is the network boundary. Off-by-one here means crashes or exploits. We need boundary conditions: exactly 1 byte, exactly max, and the encode→readLength round-trip contract.

**Step 1: Write the failing tests**

Add these tests inside the existing `FrameTests` suite in `Tests/SharedTests/ProtocolTests.swift`:

```swift
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
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter FrameTests 2>&1 | tail -25`
Expected: PASS

**Step 3: Commit**

```bash
git add Tests/SharedTests/ProtocolTests.swift
git commit -m "test: frame boundary conditions — exact max, min, off-by-one, garbage input"
```

---

### Task 4: AuthRequest/AuthResponse Init Verification

**Files:**
- Modify: `Tests/SharedTests/ProtocolTests.swift`

The message constructors auto-populate fields (version, hostname, base64 encoding). If someone changes the init and breaks the encoding, serialization silently corrupts. Test the contract.

**Step 1: Write the failing tests**

Add a new suite in `Tests/SharedTests/ProtocolTests.swift`:

```swift
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
        #expect(resp.error == nil)
    }

    @Test("AuthResponse denied with error, no signature")
    func authResponseDenied() {
        let resp = AuthResponse(approved: false, error: "denied by user")
        #expect(resp.approved == false)
        #expect(resp.signature == nil)
        #expect(resp.publicKey == nil)
        #expect(resp.error == "denied by user")
    }

    @Test("AuthResponse minimal approved, no optional fields")
    func authResponseMinimal() {
        let resp = AuthResponse(approved: true)
        #expect(resp.approved == true)
        #expect(resp.signature == nil)
        #expect(resp.publicKey == nil)
        #expect(resp.error == nil)
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter MessageTests 2>&1 | tail -20`
Expected: PASS

**Step 3: Commit**

```bash
git add Tests/SharedTests/ProtocolTests.swift
git commit -m "test: message construction contracts — field encoding, defaults, optional fields"
```

---

### Task 5: DER Certificate Structure Tests

**Files:**
- Modify: `Tests/SharedTests/TLSCertTests.swift`

The self-signed cert builder is hand-rolled ASN.1 DER. We already test that it parses, but we don't verify the structure is correct (right subject CN, right key algorithm, v3 extensions present). A subtle DER encoding bug could pass SecCertificateCreateWithData but fail on strict TLS stacks.

**Step 1: Write the failing tests**

Add to the existing `TLSCertTests` suite in `Tests/SharedTests/TLSCertTests.swift`:

```swift
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
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter TLSCertTests 2>&1 | tail -20`
Expected: PASS

**Step 3: Commit**

```bash
git add Tests/SharedTests/TLSCertTests.swift
git commit -m "test: DER cert structure — subject CN, key uniqueness, size sanity, TLSPeerInfo"
```

---

### Task 6: AuthProof Compute Direct Tests

**Files:**
- Modify: `Tests/SharedTests/AuthPrimitivesTests.swift`

The `compute()` function is currently tested only indirectly through `verify()`. That means if both are broken in the same way, we'd never know. Test the raw output properties.

**Step 1: Write the failing tests**

Add to the existing `AuthProofTests` suite in `Tests/SharedTests/AuthPrimitivesTests.swift`:

```swift
@Test("compute returns 32-byte HMAC-SHA256")
func computeReturns32Bytes() {
    let key = SymmetricKey(size: .bits256)
    let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
    let result = AuthProof.compute(psk: key, nonce: nonce)
    #expect(result.count == 32)  // SHA-256 output is always 32 bytes
}

@Test("compute is deterministic for same inputs")
func computeIsDeterministic() {
    let key = SymmetricKey(size: .bits256)
    let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
    let r1 = AuthProof.compute(psk: key, nonce: nonce)
    let r2 = AuthProof.compute(psk: key, nonce: nonce)
    #expect(r1 == r2)
}

@Test("compute differs for different keys")
func computeDiffersForDifferentKeys() {
    let k1 = SymmetricKey(size: .bits256)
    let k2 = SymmetricKey(size: .bits256)
    let nonce = Data(repeating: 0x01, count: OTA.nonceSize)
    #expect(AuthProof.compute(psk: k1, nonce: nonce) != AuthProof.compute(psk: k2, nonce: nonce))
}

@Test("compute differs for different nonces")
func computeDiffersForDifferentNonces() {
    let key = SymmetricKey(size: .bits256)
    let n1 = Data(repeating: 0x01, count: OTA.nonceSize)
    let n2 = Data(repeating: 0x02, count: OTA.nonceSize)
    #expect(AuthProof.compute(psk: key, nonce: n1) != AuthProof.compute(psk: key, nonce: n2))
}

@Test("verify rejects empty-string proof")
func verifyRejectsEmptyString() {
    let key = SymmetricKey(size: .bits256)
    let nonce = Data(repeating: 0x42, count: OTA.nonceSize)
    #expect(AuthProof.verify(proofBase64: "", nonce: nonce, psk: key) == false)
}
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter AuthProofTests 2>&1 | tail -20`
Expected: PASS

**Step 3: Commit**

```bash
git add Tests/SharedTests/AuthPrimitivesTests.swift
git commit -m "test: direct AuthProof.compute tests — output size, determinism, uniqueness, empty-string"
```

---

## Phase 2: Extract & Test Business Logic (Unit Tests — Still Base of Pyramid)

The server's request handling and the client's file operations are currently untestable private methods. We extract the pure logic into testable public functions. This is not "refactoring for fun" — this is "making the security-critical code path actually verifiable."

---

### Task 7: Extract Server Request Validation

**Files:**
- Create: `Sources/Shared/RequestValidation.swift`
- Modify: `Sources/ServerLib/ServerCommand.swift`

The server's `handleRequest` method validates incoming requests: decode JSON, check nonce size, verify PSK. This logic is security-critical and currently buried in a private class. Extract it into a pure function.

**Step 1: Create the extraction**

Create `Sources/Shared/RequestValidation.swift`:

```swift
import CryptoKit
import Foundation

/// Result of validating an incoming AuthRequest frame.
public enum ValidatedRequest {
    case test(hostname: String, source: String)
    case auth(nonce: Data, hostname: String, hasStoredKey: Bool, source: String)
}

/// Validates a raw AuthRequest payload. Pure function, no side effects.
/// Returns the validated request or throws with an appropriate OTAError.
public func validateAuthRequest(
    payload: Data,
    psk: SymmetricKey,
    rateLimiter: SourceRateLimiter,
    source: String
) throws -> ValidatedRequest {
    // Rate limiting
    guard rateLimiter.shouldAllow(source: source) else {
        throw OTAError.badRequest("rate limited")
    }

    // Decode
    let req = try Frame.decode(AuthRequest.self, from: payload)

    // Validate nonce
    guard let nonce = Data(base64Encoded: req.nonce), nonce.count == OTA.nonceSize else {
        throw OTAError.badRequest("invalid nonce")
    }

    // Verify PSK proof
    guard AuthProof.verify(proofBase64: req.clientProof, nonce: nonce, psk: psk) else {
        throw OTAError.authenticationFailed
    }

    // Route by mode
    if req.mode == "test" {
        return .test(hostname: req.hostname, source: source)
    }

    return .auth(nonce: nonce, hostname: req.hostname, hasStoredKey: req.hasStoredKey, source: source)
}
```

**Step 2: Update ServerCommand to use the extraction**

In `Sources/ServerLib/ServerCommand.swift`, modify the `handleRequest` method of the `Server` class. Replace the inline validation (lines 272-309) with a call to `validateAuthRequest`. The method body becomes:

```swift
private func handleRequest(_ data: Data, on conn: NWConnection) {
    let source = sourceLabel(for: conn)

    let validated: ValidatedRequest
    do {
        validated = try validateAuthRequest(
            payload: data,
            psk: psk,
            rateLimiter: rateLimiter,
            source: source
        )
    } catch let error as OTAError where error.clientDescription == "Authentication failed" {
        logErr("  rejected (bad PSK) from \(source)")
        auditLog("AUTH_FAILED source=\(source) reason=bad_psk")
        reply(.init(approved: false, error: error.clientDescription), on: conn)
        return
    } catch {
        logErr("  bad request from \(source): \(error.localizedDescription)")
        auditLog("BAD_REQUEST source=\(source) error=\(error.localizedDescription)")
        let clientError = (error as? OTAError)?.clientDescription ?? "Bad request"
        reply(.init(approved: false, error: clientError), on: conn)
        return
    }

    switch validated {
    case .test(let hostname, _):
        log("[\(source)] test request (client hostname: \(hostname)) — OK")
        auditLog("TEST_OK source=\(source) hostname=\(hostname)")
        reply(.init(approved: true), on: conn)

    case .auth(let nonce, let hostname, let hasStoredKey, _):
        let displayReason = "OTA Touch ID request from \(source)"
        log("[\(source)] auth request (client hostname: \(hostname))")

        Task {
            do {
                let signedData = nonce + self.certFingerprint
                let sig = try await sign(
                    data: signedData,
                    keyBlob: keyBlob,
                    reason: displayReason
                )
                log("  approved")
                auditLog("APPROVED source=\(source) hostname=\(hostname)")
                let pubKey: Data? = hasStoredKey ? nil : publicKeyRaw
                self.reply(
                    .init(approved: true, signature: sig.rawRepresentation, publicKey: pubKey),
                    on: conn)
            } catch {
                log("  denied (\(error.localizedDescription))")
                auditLog("DENIED source=\(source) hostname=\(hostname) error=\(error.localizedDescription)")
                reply(.init(approved: false, error: "Authentication denied"), on: conn)
            }
        }
    }
}
```

**Step 3: Run existing tests to make sure nothing broke**

Run: `swift test 2>&1 | tail -10`
Expected: All existing 28 tests PASS

**Step 4: Commit**

```bash
git add Sources/Shared/RequestValidation.swift Sources/ServerLib/ServerCommand.swift
git commit -m "refactor: extract server request validation into testable pure function"
```

---

### Task 8: Test Server Request Validation

**Files:**
- Create: `Tests/SharedTests/RequestValidationTests.swift`

Now we test the security-critical validation logic that was previously untestable. Every rejection path, every edge case.

**Step 1: Write the failing tests**

Create `Tests/SharedTests/RequestValidationTests.swift`:

```swift
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
        // Encode the full frame, then strip the 4-byte length header
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

        // First request succeeds
        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "attacker")

        // Second request is rate limited
        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "attacker")
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
        let shortNonce = Data(repeating: 0xAA, count: 16)  // Should be 32
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
        let req = AuthRequest(nonce: nonce, reason: "test")  // no clientProof
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

        // Source A uses up its budget
        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "A")
        #expect(throws: OTAError.self) {
            try validateAuthRequest(payload: payload, psk: self.psk, rateLimiter: limiter, source: "A")
        }

        // Source B is unaffected
        _ = try validateAuthRequest(payload: payload, psk: psk, rateLimiter: limiter, source: "B")
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `swift test --filter RequestValidation 2>&1 | tail -20`
Expected: All 9 tests PASS

**Step 3: Commit**

```bash
git add Tests/SharedTests/RequestValidationTests.swift
git commit -m "test: server request validation — rate limiting, PSK, nonce, garbage input"
```

---

### Task 9: Extract and Test Key Fingerprint Utility

**Files:**
- Create: `Sources/Shared/Fingerprint.swift`
- Modify: `Sources/ClientLib/ClientCommand.swift`

The `keyFingerprint()` function in ClientCommand is private but deterministic and security-visible (users see it during TOFU). If the format changes, TOFU becomes confusing. Extract and test it.

**Step 1: Create the extraction**

Create `Sources/Shared/Fingerprint.swift`:

```swift
import CryptoKit
import Foundation

/// Produces a human-readable fingerprint for a public key (16-byte SHA-256 prefix, colon-separated hex).
/// Matches SSH conventions for fingerprint display.
public func keyFingerprint(_ keyData: Data) -> String {
    let hash = SHA256.hash(data: keyData)
    return hash.prefix(16).map { String(format: "%02x", $0) }.joined(separator: ":")
}
```

**Step 2: Update ClientCommand to use the shared version**

In `Sources/ClientLib/ClientCommand.swift`, remove the private `keyFingerprint` function (lines 258-261) and use the one from Shared (it's already imported).

Remove these lines:
```swift
// [L5] 16-byte fingerprint matching SSH conventions (was 8 bytes).
private func keyFingerprint(_ keyData: Data) -> String {
    let hash = SHA256.hash(data: keyData)
    return hash.prefix(16).map { String(format: "%02x", $0) }.joined(separator: ":")
}
```

**Step 3: Run existing tests to verify nothing broke**

Run: `swift test 2>&1 | tail -10`
Expected: All existing tests PASS

**Step 4: Commit the extraction**

```bash
git add Sources/Shared/Fingerprint.swift Sources/ClientLib/ClientCommand.swift
git commit -m "refactor: extract keyFingerprint to Shared for testability"
```

**Step 5: Write the tests**

Create `Tests/SharedTests/FingerprintTests.swift`:

```swift
import CryptoKit
import Foundation
import Testing

@testable import Shared

@Suite("Key fingerprint")
struct FingerprintTests {
    @Test("produces colon-separated hex of correct length")
    func format() {
        let data = Data(repeating: 0xAB, count: 65)  // typical P256 public key size
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
```

**Step 6: Run the fingerprint tests**

Run: `swift test --filter FingerprintTests 2>&1 | tail -15`
Expected: All 4 tests PASS

**Step 7: Commit**

```bash
git add Tests/SharedTests/FingerprintTests.swift
git commit -m "test: key fingerprint format, determinism, uniqueness, lowercase hex"
```

---

### Task 10: Client PSK Validation Tests

**Files:**
- Create: `Tests/SharedTests/ClientPairTests.swift`

`ClientCommand.pair()` validates PSK format and writes to disk with atomic operations. This is the security boundary where user input enters the system. Test it with a temp directory.

**Step 1: Write the tests**

Create `Tests/SharedTests/ClientPairTests.swift`:

```swift
import Foundation
import Testing

@testable import ClientLib
@testable import Shared

@Suite("Client pair validation")
struct ClientPairTests {
    @Test("pair rejects non-base64 input")
    func rejectsNonBase64() {
        #expect(throws: OTAError.self) {
            try ClientCommand.pair(pskBase64: "not-valid-base64!!!")
        }
    }

    @Test("pair rejects base64 that decodes to wrong size")
    func rejectsWrongSize() {
        // 16 bytes instead of 32
        let shortKey = Data(repeating: 0xAA, count: 16).base64EncodedString()
        #expect(throws: OTAError.self) {
            try ClientCommand.pair(pskBase64: shortKey)
        }
    }

    @Test("pair rejects empty string")
    func rejectsEmpty() {
        #expect(throws: OTAError.self) {
            try ClientCommand.pair(pskBase64: "")
        }
    }

    @Test("trustKey rejects non-base64 input")
    func trustKeyRejectsNonBase64() {
        #expect(throws: OTAError.self) {
            try ClientCommand.trustKey(base64: "definitely not base64!!!")
        }
    }
}
```

NOTE: `pair()` and `trustKey()` write to `~/.config/ota-touchid/`. The CLISmokeTests helper already uses a temp HOME directory. For unit tests that only test validation (before the file write), the throws happen before any file I/O, so these are safe to run without isolation.

**Step 2: Update Package.swift**

Add ClientLib as a dependency for SharedTests (or create a new test target). The simplest approach: add these tests to a new test target.

In `Package.swift`, add a new test target:

```swift
.testTarget(
    name: "ClientLibTests",
    dependencies: ["ClientLib", "Shared"]
),
```

And move the file to `Tests/ClientLibTests/ClientPairTests.swift`.

Actually — the simpler approach is to just add ClientLib as a dependency of SharedTests. But that creates a dependency mess. Let's create the proper target.

Create directory `Tests/ClientLibTests/` and put the test file there.

**Step 3: Run the tests**

Run: `swift test --filter ClientPairTests 2>&1 | tail -15`
Expected: All 4 tests PASS

**Step 4: Commit**

```bash
git add Tests/ClientLibTests/ClientPairTests.swift Package.swift
git commit -m "test: client PSK/key validation — rejects non-base64, wrong size, empty"
```

---

## Phase 3: Integration Tests (Top of Pyramid)

These test the protocol-level exchange between client and server components. They verify that the whole encode→send→receive→decode→validate→respond pipeline works end-to-end without needing actual hardware.

---

### Task 11: Protocol Round-Trip Integration Test

**Files:**
- Create: `Tests/CLIIntegrationTests/ProtocolIntegrationTests.swift`

Test the full protocol exchange at the data level: client builds a request frame, server-side validation processes it, server builds a response frame, client decodes it. No network, no Touch ID — just the data pipeline.

**Step 1: Write the test**

Create `Tests/CLIIntegrationTests/ProtocolIntegrationTests.swift`:

```swift
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
```

**Step 2: Run the integration tests**

Run: `swift test --filter ProtocolIntegration 2>&1 | tail -20`
Expected: All 4 tests PASS

**Step 3: Commit**

```bash
git add Tests/CLIIntegrationTests/ProtocolIntegrationTests.swift
git commit -m "test: protocol integration — full auth round-trip, test mode, denial, wrong PSK"
```

---

### Task 12: More CLI Smoke Tests

**Files:**
- Modify: `Tests/CLIIntegrationTests/CLISmokeTests.swift`

The existing CLI smoke tests cover 5 cases. Add tests for the remaining command variants and edge cases.

**Step 1: Write the tests**

Add to the `CLISmokeTests` suite in `Tests/CLIIntegrationTests/CLISmokeTests.swift`:

```swift
@Test("status runs without crashing on fresh home dir")
func statusOnFreshHome() throws {
    let result = try runCLI(["status"])
    #expect(result.status == 0)
    #expect(result.stdout.contains("OTA Touch ID Status"))
    #expect(result.stdout.contains("not found") || result.stdout.contains("present"))
}

@Test("test requires host and port together")
func testRequiresHostPortPair() throws {
    let result = try runCLI(["test", "--host", "127.0.0.1"])
    #expect(result.status == 1)
    #expect(result.stderr.contains("--host and --port must be used together"))
}

@Test("auth rejects unknown flags")
func authRejectsUnknownFlag() throws {
    let result = try runCLI(["auth", "--nope"])
    #expect(result.status == 1)
    #expect(result.stderr.contains("Unknown option"))
}

@Test("test rejects unknown flags")
func testRejectsUnknownFlag() throws {
    let result = try runCLI(["test", "--nope"])
    #expect(result.status == 1)
    #expect(result.stderr.contains("Unknown option"))
}

@Test("help shows all commands")
func helpShowsAllCommands() throws {
    let result = try runCLI(["help"])
    #expect(result.stdout.contains("setup"))
    #expect(result.stdout.contains("test"))
    #expect(result.stdout.contains("auth"))
    #expect(result.stdout.contains("status"))
    #expect(result.stdout.contains("uninstall"))
}

@Test("--help flag works like help command")
func dashDashHelp() throws {
    let result = try runCLI(["--help"])
    #expect(result.status == 0)
    #expect(result.stdout.contains("Usage:"))
}

@Test("-h flag works like help command")
func dashH() throws {
    let result = try runCLI(["-h"])
    #expect(result.status == 0)
    #expect(result.stdout.contains("Usage:"))
}
```

**Step 2: Run the smoke tests**

Run: `swift test --filter CLISmokeTests 2>&1 | tail -25`
Expected: All 12 tests PASS

**Step 3: Commit**

```bash
git add Tests/CLIIntegrationTests/CLISmokeTests.swift
git commit -m "test: CLI smoke tests — status, help variants, unknown flags, host/port pairing"
```

---

## Summary

| Phase | Tests Added | What It Covers |
|-------|------------|----------------|
| 1 | ~25 unit tests | Rate limiter boundaries, error descriptions, frame boundaries, message construction, DER cert structure, AuthProof compute |
| 2 | ~17 unit tests | Server request validation (the security-critical path), key fingerprint, client PSK validation |
| 3 | ~11 integration tests | Protocol round-trip, CLI command coverage |
| **Total** | **~53 new tests** | Bring total from 28 to ~81 |

**What remains untestable without hardware:**
- Secure Enclave key creation (requires Apple Silicon)
- Touch ID biometric signing (requires hardware)
- Actual NWConnection TLS handshake (requires network + keychain)
- Bonjour discovery (requires network services)
- iCloud Keychain sync (requires iCloud account)
- launchd agent management (requires system services)

These would need either integration test infrastructure with real hardware or protocol-level fakes. That's a separate effort and out of scope for this hardening pass.
