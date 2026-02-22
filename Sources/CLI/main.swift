import Foundation
import ServerLib
import ClientLib
import Shared

// MARK: - Subcommand Dispatch

let args = Array(CommandLine.arguments.dropFirst())
let command = args.first ?? "help"

switch command {
case "setup":
    SetupCommand.run(args: Array(args.dropFirst()))

case "test":
    var host: String?
    var port: UInt16?
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--host" where i + 1 < args.count:
            i += 1; host = args[i]
        case "--port" where i + 1 < args.count:
            i += 1
            guard let p = UInt16(args[i]) else {
                fputs("Error: Invalid port '\(args[i])'\n", stderr)
                exit(1)
            }
            port = p
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
            exit(1)
        }
        i += 1
    }
    if (host == nil) != (port == nil) {
        fputs("Error: --host and --port must be used together\n", stderr)
        exit(1)
    }
    ClientCommand.test(host: host, port: port)

case "auth":
    var reason = "authentication"
    var host: String?
    var port: UInt16?
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--reason" where i + 1 < args.count:
            i += 1; reason = args[i]
        case "--host" where i + 1 < args.count:
            i += 1; host = args[i]
        case "--port" where i + 1 < args.count:
            i += 1
            guard let p = UInt16(args[i]) else {
                fputs("Error: Invalid port '\(args[i])'\n", stderr)
                exit(1)
            }
            port = p
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
            exit(1)
        }
        i += 1
    }
    if (host == nil) != (port == nil) {
        fputs("Error: --host and --port must be used together\n", stderr)
        exit(1)
    }
    ClientCommand.auth(reason: reason, host: host, port: port)

case "status":
    StatusCommand.run()

case "uninstall":
    UninstallCommand.run()

case "serve":
    // Hidden command — used by launchd
    ServerCommand.run()

case "help", "--help", "-h":
    printUsage()
    exit(0)

default:
    fputs("Unknown command: \(command)\n\n", stderr)
    printUsage()
    exit(1)
}

// MARK: - Setup Command

enum SetupCommand {
    static func run(args: [String]) {
        // Parse flags
        var role: String?
        var pskOverride: String?
        var i = 0
        while i < args.count {
            switch args[i] {
            case "--server":
                role = "server"
            case "--client":
                role = "client"
            case "--psk" where i + 1 < args.count:
                i += 1; pskOverride = args[i]
            default:
                fputs("Unknown option: \(args[i])\n", stderr)
                exit(1)
            }
            i += 1
        }

        // Interactive prompt if no role flag
        if role == nil {
            fputs("Set up this Mac as:\n  1) Server (has Touch ID)\n  2) Client (remote machine)\nChoice [1/2]: ", stderr)
            guard let line = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines) else {
                fputs("No input. Aborting.\n", stderr)
                exit(1)
            }
            switch line {
            case "1", "server": role = "server"
            case "2", "client": role = "client"
            default:
                fputs("Invalid choice. Aborting.\n", stderr)
                exit(1)
            }
        }

        switch role {
        case "server":
            setupServer()
        case "client":
            setupClient(pskBase64: pskOverride)
        default:
            fatalError("unreachable")
        }
    }

    private static func setupServer() {
        do {
            let config = try ServerCommand.generateConfig()

            // Attempt iCloud Keychain publish (best-effort)
            do {
                try ServerCommand.publishToKeychain(
                    pskBase64: config.pskBase64,
                    publicKeyBase64: config.publicKeyBase64
                )
                fputs("PSK and public key saved to iCloud Keychain.\n", stderr)
            } catch {
                fputs("Warning: Could not save to iCloud Keychain (\(error.localizedDescription)).\n", stderr)
                fputs("Clients on other Macs will need the PSK manually.\n", stderr)
            }

            // Resolve binary path for launchd plist
            let binaryPath: String
            if let resolved = resolveRealBinaryPath() {
                binaryPath = resolved
            } else {
                binaryPath = CommandLine.arguments[0]
            }

            // Write launchd plist
            let plistDir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/LaunchAgents")
            try FileManager.default.createDirectory(at: plistDir, withIntermediateDirectories: true)

            let plistPath = plistDir.appendingPathComponent("com.ota-touchid.server.plist")
            let plistContent = launchdPlist(binaryPath: binaryPath)
            try plistContent.write(to: plistPath, atomically: true, encoding: .utf8)

            // Load the agent (unload first in case it's already loaded)
            let unload = Process()
            unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unload.arguments = ["unload", plistPath.path]
            unload.standardOutput = FileHandle.nullDevice
            unload.standardError = FileHandle.nullDevice
            try? unload.run()
            unload.waitUntilExit()

            let load = Process()
            load.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            load.arguments = ["load", plistPath.path]
            try load.run()
            load.waitUntilExit()

            guard load.terminationStatus == 0 else {
                fputs("Warning: launchctl load failed (exit \(load.terminationStatus))\n", stderr)
                fputs("You can start the server manually: ota-touchid serve\n", stderr)
                return
            }

            print("")
            print("OTA Touch ID Server Setup Complete")
            print(String(repeating: "\u{2500}", count: 40))
            print("Server installed as launchd agent (starts on login).")
            print("")
            print("To set up a client Mac (same Apple ID — auto-pairing):")
            print("  ota-touchid setup --client")
            print("")
            print("To set up a client Mac (different Apple ID — manual PSK):")
            print("  ota-touchid setup --client --psk \(config.pskBase64)")
            print("")
            print("Then verify with:")
            print("  ota-touchid test")
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    private static func setupClient(pskBase64: String?) {
        do {
            try ClientCommand.setupClient(pskBase64: pskBase64)

            print("")
            print("OTA Touch ID Client Setup Complete")
            print(String(repeating: "\u{2500}", count: 40))
            print("Verify connectivity:")
            print("  ota-touchid test")
            print("")
            print("Authenticate:")
            print("  ota-touchid auth --reason sudo")
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    private static func resolveRealBinaryPath() -> String? {
        let arg0 = CommandLine.arguments[0]
        // If it's already absolute, resolve symlinks
        if arg0.hasPrefix("/") {
            return (try? FileManager.default.destinationOfSymbolicLink(atPath: arg0)) ?? arg0
        }
        // Try to find via `which`
        let which = Process()
        which.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        which.arguments = ["ota-touchid"]
        let pipe = Pipe()
        which.standardOutput = pipe
        try? which.run()
        which.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let path, !path.isEmpty else { return nil }
        return path
    }

    private static func launchdPlist(binaryPath: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.ota-touchid.server</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(binaryPath)</string>
                <string>serve</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>ProcessType</key>
            <string>Interactive</string>
            <key>StandardOutPath</key>
            <string>/tmp/ota-touchid.out.log</string>
            <key>StandardErrorPath</key>
            <string>/tmp/ota-touchid.err.log</string>
        </dict>
        </plist>
        """
    }
}

// MARK: - Status Command

enum StatusCommand {
    static func run() {
        print("OTA Touch ID Status")
        print(String(repeating: "\u{2500}", count: 40))

        let fm = FileManager.default
        let configDir = OTA.configDir

        // Config directory
        if fm.fileExists(atPath: configDir.path) {
            print("Config dir:  \(configDir.path) (exists)")
        } else {
            print("Config dir:  \(configDir.path) (not found)")
        }

        // Server key
        let serverKeyPath = configDir.appendingPathComponent("server.key").path
        print("Server key:  \(fm.fileExists(atPath: serverKeyPath) ? "present" : "not found")")

        // Client-side status
        ClientCommand.status()

        // iCloud Keychain PSK
        let keychainPSK = SyncedKeychain.read(account: .preSharedKey) != nil
        print("iCloud PSK:  \(keychainPSK ? "present" : "not found")")

        // LaunchD service
        print("")
        let list = Process()
        list.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        list.arguments = ["list", "com.ota-touchid.server"]
        let pipe = Pipe()
        list.standardOutput = pipe
        list.standardError = Pipe()  // suppress stderr
        try? list.run()
        list.waitUntilExit()

        if list.terminationStatus == 0 {
            print("LaunchD:     running")
        } else {
            print("LaunchD:     not loaded (run 'ota-touchid setup --server' to install)")
        }
    }
}

// MARK: - Uninstall Command

enum UninstallCommand {
    static func run() {
        let plistPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.ota-touchid.server.plist")

        // Unload the agent
        if FileManager.default.fileExists(atPath: plistPath.path) {
            let unload = Process()
            unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unload.arguments = ["unload", plistPath.path]
            unload.standardOutput = FileHandle.nullDevice
            unload.standardError = FileHandle.nullDevice
            try? unload.run()
            unload.waitUntilExit()

            try? FileManager.default.removeItem(at: plistPath)
            print("LaunchD agent unloaded and plist removed.")
        } else {
            print("No launchd plist found.")
        }

        // Ask about Keychain items
        fputs("Remove iCloud Keychain items? [y/N] ", stderr)
        if let line = readLine()?.lowercased(), line == "y" || line == "yes" {
            SyncedKeychain.delete(account: .preSharedKey)
            SyncedKeychain.delete(account: .serverPublicKey)
            print("Keychain items removed.")
        } else {
            print("Keychain items kept.")
        }

        // Ask about config
        fputs("Remove config directory (~/.config/ota-touchid)? [y/N] ", stderr)
        if let line = readLine()?.lowercased(), line == "y" || line == "yes" {
            do {
                try FileManager.default.removeItem(at: OTA.configDir)
                print("Config directory removed.")
            } catch {
                fputs("Error removing config: \(error.localizedDescription)\n", stderr)
            }
        } else {
            print("Config directory kept.")
        }
    }
}

// MARK: - Usage

func printUsage() {
    print("""
        OTA Touch ID \u{2014} Over-the-air Touch ID authentication

        Usage:
          ota-touchid setup [--server | --client] [--psk <base64>]
              Interactive install. Sets up server (Touch ID Mac) or client (remote Mac).
              Same-Apple-ID devices auto-pair via iCloud Keychain.

          ota-touchid test [--host <ip> --port <port>]
              Verify connectivity to server (no Touch ID prompt).

          ota-touchid auth [--reason <text>] [--host <ip> --port <port>]
              Authenticate via Touch ID. Exit 0 = approved, 1 = denied.

          ota-touchid status
              Show configuration and service status.

          ota-touchid uninstall
              Stop service, remove launchd agent, optionally clean up.

        Quick start (server Mac):
          brew install pproenca/tap/ota-touchid
          ota-touchid setup --server

        Quick start (client Mac, same Apple ID):
          brew install pproenca/tap/ota-touchid
          ota-touchid setup --client
          ota-touchid test
          ota-touchid auth --reason sudo
        """)
}
