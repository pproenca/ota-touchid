import Foundation
import ServerLib
import ClientLib
import Shared

// MARK: - Subcommand Dispatch

let args = Array(CommandLine.arguments.dropFirst())
let command = args.first ?? "help"

switch command {
case "setup":
    SetupCommand.run()

case "pair":
    guard args.count >= 2 else {
        fputs("Usage: ota-touchid pair <psk-base64>\n", stderr)
        exit(1)
    }
    do {
        try ClientCommand.pair(pskBase64: args[1])
    } catch {
        fputs("Error: \(error.localizedDescription)\n", stderr)
        exit(1)
    }

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

case "serve":
    ServerCommand.run()

case "status":
    StatusCommand.run()

case "uninstall":
    UninstallCommand.run()

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
    static func run() {
        do {
            let pskBase64 = try ServerCommand.generateConfig()

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

            // Load the agent
            let unload = Process()
            unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unload.arguments = ["unload", plistPath.path]
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
            print("OTA Touch ID Setup Complete")
            print(String(repeating: "\u{2500}", count: 40))
            print("Server installed as launchd agent (starts on login).")
            print("")
            print("To pair a client, run on the client machine:")
            print("  ota-touchid pair \(pskBase64)")
            print("")
            print("Then authenticate with:")
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
            print("LaunchD:     not loaded (run 'ota-touchid setup' to install)")
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
            try? unload.run()
            unload.waitUntilExit()

            try? FileManager.default.removeItem(at: plistPath)
            print("LaunchD agent unloaded and plist removed.")
        } else {
            print("No launchd plist found.")
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
        OTA Touch ID — Over-the-air Touch ID authentication

        Usage:
          ota-touchid setup                        Generate keys, install server as launchd agent
          ota-touchid pair <psk>                   Save PSK on client machine
          ota-touchid auth [options]               Authenticate via Touch ID (exit 0=ok, 1=denied)
          ota-touchid serve                        Run server in foreground
          ota-touchid status                       Show config & service status
          ota-touchid uninstall                    Stop service, remove launchd agent
          ota-touchid help                         Show this help

        Auth options:
          --reason <text>                          Reason shown in Touch ID prompt (default: "authentication")
          --host <ip> --port <port>                Direct connection (skip Bonjour discovery)

        Quick start (server):
          brew install pproenca/tap/ota-touchid
          ota-touchid setup

        Quick start (client):
          brew install pproenca/tap/ota-touchid
          ota-touchid pair <psk>                   (use PSK from server setup output)
          ota-touchid auth --reason sudo
        """)
}
