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
