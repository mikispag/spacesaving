import Darwin
import Foundation

let usage = """
    spacesaving: reclaim disk space by replacing identical files with APFS clones

    USAGE
      spacesaving scan    [options] <folder>...   Report identical files and the space clones would save
      spacesaving reclaim [options] <folder>...   Replace identical files with clones of one another
      spacesaving check   <file> <file>           Tell whether two files already share storage

    OPTIONS
      -s, --source <folder>    Use files in <folder> as clone sources but never change them (repeatable)
      -m, --min-size <size>    Ignore files smaller than <size>, e.g. 4K, 1M, 2G (default 64K)
      -x, --exclude <regex>    Skip folders whose path matches <regex> (repeatable)
          --skip-packages      Don't look inside packages such as .app bundles
          --include-executables
                               Also consider Mach-O executables, libraries and static archives
          --allow-library      Look inside Library folders
          --allow-cloud        Look inside iCloud Drive and other cloud-synced folders
          --allow-photos       Look inside Photos libraries (quit Photos before reclaiming)
      -l, --list               List every set of identical files
      -v, --verbose            Explain each skipped file and each replacement
          --delete             reclaim: delete replaced originals instead of moving them to the Trash
      -y, --yes                reclaim: don't ask for confirmation
      -h, --help               Show this help

    Originals are moved to the Trash by default, so space is freed once the Trash is emptied.
    """

func formatBytes(_ bytes: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
}

func formatCount(_ count: Int) -> String {
    NumberFormatter.localizedString(from: NSNumber(value: count), number: .decimal)
}

func plural(_ count: Int, _ noun: String) -> String {
    "\(formatCount(count)) \(noun)\(count == 1 ? "" : "s")"
}

func printError(_ message: String) {
    fputs("\(message)\n", stderr)
}

func parseSize(_ text: String) -> Int64? {
    let units: [Character: Double] = ["K": 0x1p10, "M": 0x1p20, "G": 0x1p30, "T": 0x1p40]
    var number = text.uppercased()
    if number.hasSuffix("B") { number.removeLast() }
    var multiplier = 1.0
    if let unit = number.last, let value = units[unit] {
        multiplier = value
        number.removeLast()
    }
    guard let value = Double(number), value >= 0 else { return nil }
    return Int64(value * multiplier)
}

struct Invocation {
    var command = ""
    var scan = ScanOptions()
    var reclaim = ReclaimOptions()
    var list = false
    var assumeYes = false
    var files: [String] = []
}

func parseArguments(_ arguments: [String]) throws -> Invocation {
    var invocation = Invocation()
    var remaining = arguments[...]
    guard let command = remaining.popFirst(), command != "-h", command != "--help" else { throw ToolError(usage) }
    guard ["scan", "reclaim", "check"].contains(command) else { throw ToolError("Unknown command \(command)\n\n\(usage)") }
    invocation.command = command

    func value(for option: String) throws -> String {
        guard let value = remaining.popFirst() else { throw ToolError("\(option) needs a value") }
        return value
    }
    while let argument = remaining.popFirst() {
        switch argument {
        case "-s", "--source": invocation.scan.sourceRoots.append(try value(for: argument))
        case "-m", "--min-size":
            let text = try value(for: argument)
            guard let size = parseSize(text) else { throw ToolError("Invalid size: \(text)") }
            invocation.scan.minimumSize = size
        case "-x", "--exclude": invocation.scan.excludePatterns.append(try value(for: argument))
        case "--skip-packages": invocation.scan.scanPackages = false
        case "--include-executables": invocation.scan.includeExecutables = true
        case "--allow-library": invocation.scan.allowLibrary = true
        case "--allow-cloud": invocation.scan.allowCloud = true
        case "--allow-photos": invocation.scan.allowPhotos = true
        case "-l", "--list": invocation.list = true
        case "-v", "--verbose":
            invocation.scan.verbose = true
            invocation.reclaim.verbose = true
        case "--delete": invocation.reclaim.useTrash = false
        case "-y", "--yes": invocation.assumeYes = true
        case "-h", "--help": throw ToolError(usage)
        case "--": invocation.files += remaining
            remaining = []
        default:
            if argument.hasPrefix("-") { throw ToolError("Unknown option \(argument)\n\n\(usage)") }
            invocation.files.append(argument)
        }
    }
    if command == "check" {
        guard invocation.files.count == 2 else { throw ToolError("check needs exactly two files") }
    } else {
        guard !invocation.files.isEmpty else { throw ToolError("\(command) needs at least one folder") }
        invocation.scan.roots = invocation.files
    }
    return invocation
}

// MARK: - Commands

func printReport(_ report: ScanReport, list: Bool) {
    let groups = report.replaceableGroups
    print("Scanned \(plural(report.files, "file")) (\(formatBytes(report.bytes))) in \(plural(report.folders, "folder")).")
    let alreadyShared = report.groups.reduce(0) { $0 + $1.alreadyShared.count }
    if alreadyShared > 0 {
        print("\(plural(alreadyShared, "file")) already \(alreadyShared == 1 ? "shares" : "share") storage with an identical file.")
    }
    if groups.isEmpty {
        print("No identical files can be replaced with clones.")
    } else {
        let targets = groups.reduce(0) { $0 + $1.targets.count }
        print("Found \(plural(groups.count, "set")) of identical files: \(plural(targets, "file")) can be replaced with clones.")
        print("Reclaimable: \(formatBytes(report.reclaimableBytes))")
    }
    if !report.skipped.isEmpty {
        let reasons = report.skipped.sorted { $0.value > $1.value }.map { "\(formatCount($0.value)) \($0.key)" }
        print("Skipped: \(reasons.joined(separator: "; ")).")
    }
    if !report.issues.isEmpty {
        print("\(plural(report.issues.count, "file")) could not be read\(list ? ":" : " (use --list to see them).")")
        if list { report.issues.forEach { print("  \($0)") } }
    }

    guard list, !groups.isEmpty else { return }
    print("\n  = clone source   + replaced with a clone   ~ already a clone   ! kept as is")
    for group in groups {
        print("\n\(formatBytes(group.size)) × \(group.fileCount): reclaim \(formatBytes(group.reclaimableBytes))")
        print("  = \(group.source.path)")
        group.targets.forEach { print("  + \($0.path)") }
        group.alreadyShared.forEach { print("  ~ \($0.path)") }
        group.kept.forEach { print("  ! \($0.file.path) (\($0.reason))") }
    }
}

final class StopRequest {
    private let lock = NSLock()
    private var requested = false

    var isRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return requested
    }

    func request() {
        lock.lock()
        requested = true
        lock.unlock()
    }
}

func isPhotosRunning() -> Bool {
    let pgrep = Process()
    pgrep.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
    pgrep.arguments = ["-x", "Photos"]
    pgrep.standardOutput = FileHandle.nullDevice
    guard (try? pgrep.run()) != nil else { return false }
    pgrep.waitUntilExit()
    return pgrep.terminationStatus == 0
}

func confirm(_ question: String) -> Bool {
    print("\(question) [y/N] ", terminator: "")
    fflush(stdout)
    guard let answer = readLine()?.lowercased() else { return false }
    return answer == "y" || answer == "yes"
}

func runReclaim(_ invocation: Invocation, report: ScanReport) throws -> Int32 {
    let groups = report.replaceableGroups
    guard !groups.isEmpty else { return 0 }
    if groups.contains(where: { $0.targets.contains { $0.path.contains(".photoslibrary/") } }), isPhotosRunning() {
        throw ToolError("Quit Photos before reclaiming files inside a Photos library.")
    }
    let count = groups.reduce(0) { $0 + $1.targets.count }
    let disposal = invocation.reclaim.useTrash ? "moving the originals to the Trash" : "deleting the originals"
    if !invocation.assumeYes {
        guard isatty(STDIN_FILENO) != 0 else { throw ToolError("Pass --yes to reclaim without a terminal.") }
        guard confirm("\nReplace \(plural(count, "file")) with clones, \(disposal)?") else { return 1 }
    }

    let stop = StopRequest()
    let signals = [SIGINT, SIGTERM].map { number -> DispatchSourceSignal in
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
        source.setEventHandler {
            stop.request()
            printError("\nStopping after the current file…")
        }
        source.resume()
        return source
    }
    defer { signals.forEach { $0.cancel() } }

    let summary = Reclaimer(options: invocation.reclaim, log: printError).run(groups) { stop.isRequested }
    print("\nReplaced \(plural(summary.replaced, "file")) with clones.")
    if summary.freedBytes > 0 {
        print(invocation.reclaim.useTrash
            ? "Empty the Trash to free \(formatBytes(summary.freedBytes))."
            : "Freed \(formatBytes(summary.freedBytes)).")
    }
    if !summary.skipped.isEmpty {
        print("Skipped \(plural(summary.skipped.count, "file")):")
        summary.skipped.forEach { print("  \($0.path): \($0.reason)") }
    }
    if !summary.failed.isEmpty {
        print("Failed on \(plural(summary.failed.count, "file")):")
        summary.failed.forEach { print("  \($0.path): \($0.reason)") }
    }
    if !summary.warnings.isEmpty {
        print("Warnings:")
        summary.warnings.forEach { print("  \($0)") }
    }
    if let reason = summary.stopReason { print(reason) }
    return summary.failed.isEmpty && summary.stopReason == nil ? 0 : 1
}

func runCheck(_ paths: [String]) throws -> Int32 {
    let descriptors = try paths.map(openForReading)
    defer { descriptors.forEach { close($0) } }
    let stats = try zip(descriptors, paths).map { try statDescriptor($0, $1) }
    for (index, path) in paths.enumerated() {
        let info = cloneInfo(fd: descriptors[index])
        let clone = info.map { "clone ID \($0.cloneID)\($0.mayShareBlocks ? ", may share blocks" : "")" } ?? "clone ID unavailable"
        print("\(path)\n  \(formatBytes(stats[index].size)), \(formatBytes(stats[index].allocatedBytes)) allocated, inode \(stats[index].inode), \(clone)")
    }
    if stats[0].device == stats[1].device, stats[0].inode == stats[1].inode {
        print("Both paths are the same file (hard links).")
        return 0
    }
    let identical = try stats[0].size == stats[1].size
        && sameContents(descriptors[0], descriptors[1], size: stats[0].size, paths: (paths[0], paths[1]))
    print("Identical contents: \(identical ? "yes" : "no")")
    switch shareStorage(descriptors[0], descriptors[1]) {
    case true?: print("Share storage: yes, they are clones")
    case false?: print("Share storage: no")
    case nil: print("Share storage: unknown")
    }
    return 0
}

public func runCLI(arguments: [String]) -> Int32 {
    do {
        let invocation = try parseArguments(arguments)
        if invocation.command == "check" {
            return try runCheck(invocation.files)
        }
        let report = try Scanner(options: invocation.scan, log: printError).scan()
        printReport(report, list: invocation.list)
        if invocation.command == "reclaim" {
            return try runReclaim(invocation, report: report)
        }
        return 0
    } catch let error as ToolError {
        printError(error.description)
        return error.description == usage ? 0 : 2
    } catch {
        printError("\(error)")
        return 2
    }
}
