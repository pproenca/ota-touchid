import Foundation
import Testing

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
        #expect(result.stderr.contains("--host and --port must be used together"))
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
}

private struct CLIResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

private func runCLI(_ args: [String]) throws -> CLIResult {
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
    try process.run()
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
