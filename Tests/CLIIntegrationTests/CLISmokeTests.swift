import Foundation
import Testing
import Shared

@Suite("CLI smoke tests")
struct CLISmokeTests {
    @Test("help exits 0 and shows usage")
    func helpCommand() throws {
        let result = try runCLI(["help"])
        #expect(result.status == 0)
        #expect(result.stdout.contains("Usage:"))
    }

    @Test("unknown command exits 1 with an error")
    func unknownCommand() throws {
        let result = try runCLI(["wat"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Unknown command"))
    }

    @Test("auth requires host and port together")
    func authRequiresHostPortPair() throws {
        let result = try runCLI(["auth", "--port", "31337"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("--port requires --host"))
    }

    @Test("test rejects invalid port values")
    func testRejectsInvalidPort() throws {
        let result = try runCLI(["test", "--host", "127.0.0.1", "--port", "not-a-port"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Invalid port"))
    }

    @Test("setup rejects unknown flags")
    func setupRejectsUnknownFlag() throws {
        let result = try runCLI(["setup", "--nope"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Unknown option"))
    }

    @Test("pair command rejects invalid PSK values")
    func pairRejectsInvalidPSK() throws {
        let result = try runCLI(["pair", "not-base64"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("invalid PSK"))
    }

    @Test("pair command requires a PSK argument")
    func pairRequiresArgument() throws {
        let result = try runCLI(["pair"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Usage: ota-touchid pair"))
    }

    @Test("pair command can read PSK from stdin")
    func pairReadsFromStdin() throws {
        let psk = Data(repeating: 0x11, count: 32).base64EncodedString()
        let result = try runCLI(["pair", "--stdin"], stdin: "\(psk)\n")
        #expect(result.status == 0)
        #expect(result.stdout.contains("PSK saved"))
    }

    @Test("pair command imports pairing bundle token")
    func pairImportsBundle() throws {
        let psk = Data(repeating: 0x22, count: 32).base64EncodedString()
        let pub = Data(repeating: 0x33, count: 65).base64EncodedString()
        let token = try PairingBundle(
            pskBase64: psk,
            serverPublicKeyBase64: pub,
            endpointHint: EndpointHint(host: "server.local", port: OTA.defaultPort)
        ).encodeToken()
        let result = try runCLI(["pair", token])
        #expect(result.status == 0)
        #expect(result.stdout.contains("Pairing bundle imported."))
    }

    @Test("trust command rejects invalid public key")
    func trustRejectsInvalidKey() throws {
        let result = try runCLI(["trust", "not-base64"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("invalid base64 public key"))
    }

    @Test("status runs without crashing on fresh home dir")
    func statusOnFreshHome() throws {
        let result = try runCLI(["status"])
        #expect(result.status == 0)
        #expect(result.stdout.contains("OTA Touch ID Status"))
        #expect(result.stdout.contains("not found") || result.stdout.contains("present"))
    }

    @Test("test requires host and port together (host only)")
    func testRequiresHostPortPair() throws {
        let result = try runCLI(["test", "--host", "127.0.0.1"])
        #expect(result.status == 0 || result.status == 1)
    }

    @Test("auth rejects unknown flags")
    func authRejectsUnknownFlag() throws {
        let result = try runCLI(["auth", "--nope"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Unknown option"))
    }

    @Test("enroll rejects invalid port values")
    func enrollRejectsInvalidPort() throws {
        let result = try runCLI(["enroll", "--host", "127.0.0.1", "--port", "not-a-port"])
        #expect(result.status == 1)
        #expect(result.stderr.contains("Invalid port"))
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
        #expect(result.stdout.contains("pair"))
        #expect(result.stdout.contains("trust"))
        #expect(result.stdout.contains("enroll"))
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
}

private struct CLIResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

private func runCLI(_ args: [String], stdin: String? = nil) throws -> CLIResult {
    let fm = FileManager.default
    let repoRoot = workspaceRoot()
    let executable = try findExecutable(in: repoRoot)

    let tempHome = fm.temporaryDirectory.appendingPathComponent("ota-touchid-test-home-\(UUID().uuidString)")
    try fm.createDirectory(at: tempHome, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempHome) }

    let outPipe = Pipe()
    let errPipe = Pipe()

    let process = Process()
    process.executableURL = executable
    process.arguments = args
    process.currentDirectoryURL = repoRoot
    var env = ProcessInfo.processInfo.environment
    env["HOME"] = tempHome.path
    process.environment = env
    process.standardOutput = outPipe
    process.standardError = errPipe

    let inPipe = Pipe()
    if stdin != nil {
        process.standardInput = inPipe
    }

    try process.run()
    if let stdin {
        inPipe.fileHandleForWriting.write(Data(stdin.utf8))
        try? inPipe.fileHandleForWriting.close()
    }
    process.waitUntilExit()

    let stdout = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let stderr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return CLIResult(status: process.terminationStatus, stdout: stdout, stderr: stderr)
}

private func workspaceRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // CLIIntegrationTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // repo root
}

private func findExecutable(in root: URL) throws -> URL {
    let fm = FileManager.default
    let build = root.appendingPathComponent(".build")
    let candidates = [
        build.appendingPathComponent("debug/ota-touchid"),
        build.appendingPathComponent("arm64-apple-macosx/debug/ota-touchid"),
        build.appendingPathComponent("x86_64-apple-macosx/debug/ota-touchid"),
    ]

    for candidate in candidates where fm.isExecutableFile(atPath: candidate.path) {
        return candidate
    }

    if let enumerator = fm.enumerator(at: build, includingPropertiesForKeys: nil) {
        for case let fileURL as URL in enumerator {
            guard fileURL.lastPathComponent == "ota-touchid" else { continue }
            let path = fileURL.path
            if path.contains("/debug/"), fm.isExecutableFile(atPath: path) {
                return fileURL
            }
        }
    }

    throw NSError(
        domain: "CLISmokeTests",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Could not find built ota-touchid binary under \(build.path)"])
}
