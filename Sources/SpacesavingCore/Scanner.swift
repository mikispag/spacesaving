import CryptoKit
import Darwin
import Foundation

struct ScanOptions {
    var roots: [String] = []
    var sourceRoots: [String] = []
    var minimumSize: Int64 = 64 * 1024
    var excludePatterns: [String] = []
    var scanPackages = true
    var includeExecutables = false
    var allowLibrary = false
    var allowCloud = false
    var allowPhotos = false
    var verbose = false
}

struct ScannedFile {
    let path: String
    let stat: FileStat
    /// Why the file may serve as a clone source but must never be replaced.
    let keepReason: String?
}

struct DuplicateGroup {
    let source: ScannedFile
    /// Identical files that already share all of their storage with the source.
    let alreadyShared: [ScannedFile]
    /// Files to replace with clones of the source. Files in the same set already share storage
    /// with each other, so a set's space is freed only once all of its files are replaced.
    let targetSets: [[ScannedFile]]
    /// Identical files that stay as they are.
    let kept: [(file: ScannedFile, reason: String)]

    var size: Int64 { source.stat.size }
    var targets: [ScannedFile] { targetSets.flatMap { $0 } }
    var fileCount: Int { 1 + alreadyShared.count + targets.count + kept.count }
    var reclaimableBytes: Int64 { targetSets.reduce(0) { $0 + reclaimableBytes(of: $1) } }

    func reclaimableBytes(of set: [ScannedFile]) -> Int64 {
        set.map(\.stat.allocatedBytes).max() ?? 0
    }
}

struct ScanReport {
    var files = 0
    var folders = 0
    var bytes: Int64 = 0
    var skipped: [String: Int] = [:]
    var groups: [DuplicateGroup] = []
    var issues: [String] = []

    var replaceableGroups: [DuplicateGroup] { groups.filter { !$0.targetSets.isEmpty } }
    var reclaimableBytes: Int64 { groups.reduce(0) { $0 + $1.reclaimableBytes } }
}

private struct ExclusionRule {
    let regex: NSRegularExpression
    let reason: String

    init(_ pattern: String, _ reason: String) throws {
        do {
            regex = try NSRegularExpression(pattern: pattern)
        } catch {
            throw ToolError("Invalid pattern \(pattern): \(error.localizedDescription)")
        }
        self.reason = reason
    }

    func matches(_ path: String) -> Bool {
        regex.firstMatch(in: path, range: NSRange(path.startIndex..., in: path)) != nil
    }
}

final class Scanner {
    private let options: ScanOptions
    private let rules: [ExclusionRule]
    private let log: (String) -> Void
    private var report = ScanReport()
    private var files: [ScannedFile] = []
    private var seen = Set<[UInt64]>()
    private var writableFolders: [String: Bool] = [:]

    init(options: ScanOptions, log: @escaping (String) -> Void) throws {
        self.options = options
        self.log = log
        rules = try Scanner.exclusionRules(for: options)
    }

    /// Built-in exclusions for system locations, protected Library folders, Trash, and volume metadata.
    private static func exclusionRules(for options: ScanOptions) throws -> [ExclusionRule] {
        var rules = [
            try ExclusionRule(#"^(?:/Volumes/[^/]+)?/(?:System|\.(?:vol|resolve|nofollow))(?:/|$)"#, "system location"),
            try ExclusionRule(
                #"^(?:/Volumes/[^/]+)?/(?:Users/[^/]+/)?Library/(?:Keychains|Containers|Group Containers|Backblaze[^/]*|Application Support/(?:com\.apple\.TCC|FileProvider))(?:/|$)"#,
                "protected Library folder"),
            try ExclusionRule(#"^(?:/Volumes/[^/]+)?/(?:Users/[^/]+/)?\.Trash(?:es)?(?:/|$)"#, "Trash"),
            try ExclusionRule(
                #"^(?:/Volumes/[^/]+)?/(?:Users/[^/]+/)?Library/Application Support/Steam/(?:Steam\.AppBundle|steamapps/steamclean)(?:/|$)"#,
                "managed by Steam"),
            try ExclusionRule(#"^(?:/Volumes/[^/]+)?/\.(?:Spotlight-V100|fseventsd|DocumentRevisions-V100|MobileBackups)(?:/|$)"#, "volume metadata"),
        ]
        if !options.allowCloud {
            rules.append(try ExclusionRule(
                #"^(?:/Volumes/[^/]+)?/Users/[^/]+/Library/(?:CloudStorage|Mobile Documents)(?:/|$)"#, "cloud storage (see --allow-cloud)"))
        }
        if !options.allowLibrary {
            rules.append(try ExclusionRule(#"^(?:/Volumes/[^/]+)?/(?:Users/[^/]+/)?Library(?:/|$)"#, "Library folder (see --allow-library)"))
        }
        if !options.allowPhotos {
            rules.append(try ExclusionRule(#"[^/]\.photoslibrary$"#, "Photos library (see --allow-photos)"))
        }
        for pattern in options.excludePatterns {
            rules.append(try ExclusionRule(pattern, "matches --exclude"))
        }
        return rules
    }

    func scan() throws -> ScanReport {
        // Never download evicted cloud files just to read them.
        _ = setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS, IOPOL_MATERIALIZE_DATALESS_FILES_OFF)

        let roots = try options.roots.map { (try validatedRoot($0), false) } + options.sourceRoots.map { (try validatedRoot($0), true) }
        status("Scanning \(roots.map(\.0).joined(separator: ", "))…")
        for (root, sourceOnly) in roots {
            traverse(root, sourceOnly: sourceOnly)
        }

        // Same volume and size.
        let bySize = Dictionary(grouping: files) { [UInt64(bitPattern: Int64($0.stat.device)), UInt64($0.stat.size)] }
        var candidates = bySize.values.filter(worthComparing).flatMap { $0 }

        // Same first 4 KiB.
        status("Reading the start of \(formatCount(candidates.count)) files with matching sizes…")
        let headers = parallelMap(candidates, total: Int64(candidates.count), cost: { _ in 1 }) { try readHeader($0.path, size: $0.stat.size) }
        var byHeader: [[UInt64]: (files: [ScannedFile], digest: SHA256.Digest)] = [:]
        for (file, header) in zip(candidates, headers) {
            guard let header = header.value(recordingIssueIn: &report) else { continue }
            if header.isExecutable && !options.includeExecutables {
                skip(file.path, "executable or library (see --include-executables)")
                continue
            }
            let key = [UInt64(bitPattern: Int64(file.stat.device)), UInt64(file.stat.size)] + digestWords(header.digest)
            byHeader[key, default: ([], header.digest)].files.append(file)
        }
        let headerGroups = byHeader.values.filter { worthComparing($0.files) }

        // Same contents, including any resource fork.
        candidates = headerGroups.flatMap(\.files)
        let headerDigests = Dictionary(uniqueKeysWithValues: headerGroups.flatMap { group in group.files.map { ($0.path, group.digest) } })
        let hashBytes = candidates.reduce(Int64(0)) { $0 + ($1.stat.size > Int64(headerSize) ? $1.stat.size : 0) }
        status("Hashing \(formatCount(candidates.count)) candidate files (\(formatBytes(hashBytes)))…")
        let identities = parallelMap(candidates, total: hashBytes, cost: { $0.stat.size > Int64(headerSize) ? $0.stat.size : 0 }) { file in
            let data = file.stat.size <= Int64(headerSize) ? headerDigests[file.path]! : try contentDigest(file.path, size: file.stat.size)
            let fork = try readAttribute(file.path, resourceForkName).map { SHA256.hash(data: $0) }
            return [data] + (fork.map { [$0] } ?? [])
        }
        var byContent: [[UInt64]: [ScannedFile]] = [:]
        for (file, identity) in zip(candidates, identities) {
            guard let identity = identity.value(recordingIssueIn: &report) else { continue }
            let key = [UInt64(bitPattern: Int64(file.stat.device)), UInt64(file.stat.size)] + identity.flatMap(digestWords)
            byContent[key, default: []].append(file)
        }

        // Existing clones, and the choice of source.
        status("Checking existing clones…")
        report.groups = byContent.values.filter { $0.count > 1 }.compactMap(makeGroup)
            .sorted { ($0.reclaimableBytes, $1.source.path) > ($1.reclaimableBytes, $0.source.path) }
        return report
    }

    // MARK: Traversal

    private func validatedRoot(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw ToolError.posix("Cannot use", path) }
        defer { free(resolved) }
        let root = String(cString: resolved)
        guard try isAPFS(root) else { throw ToolError("\(path) is not on an APFS volume; only APFS supports clones") }
        if root == "/" || ["/Volumes", "/private", "/dev"].contains(root) {
            throw ToolError("Refusing to scan \(root); choose a folder or a volume under /Volumes")
        }
        if let rule = rules.first(where: { $0.matches(root) }) {
            throw ToolError("Refusing to scan \(root): \(rule.reason)")
        }
        return root
    }

    private func traverse(_ root: String, sourceOnly: Bool) {
        let paths: [UnsafeMutablePointer<CChar>?] = [strdup(root), nil]
        defer { free(paths[0]) }
        guard let fts = fts_open(paths, FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, nil) else {
            report.issues.append(ToolError.posix("Cannot scan", root).description)
            return
        }
        defer { fts_close(fts) }
        while let entry = fts_read(fts) {
            let path = String(cString: entry.pointee.fts_path)
            switch Int32(entry.pointee.fts_info) {
            case FTS_D:
                report.folders += 1
                if entry.pointee.fts_level > FTS_ROOTLEVEL, let reason = exclusionReason(forFolder: path) {
                    skip(path, reason)
                    fts_set(fts, entry, FTS_SKIP)
                }
            case FTS_F:
                consider(path, FileStat(entry.pointee.fts_statp.pointee), sourceOnly: sourceOnly)
            case FTS_DNR, FTS_ERR, FTS_NS:
                report.issues.append("\(path): \(String(cString: strerror(entry.pointee.fts_errno)))")
            default:
                break
            }
        }
    }

    private func exclusionReason(forFolder path: String) -> String? {
        if let rule = rules.first(where: { $0.matches(path) }) { return rule.reason }
        let url = URL(fileURLWithPath: path)
        if !options.scanPackages, url.lastPathComponent.contains("."),
           (try? url.resourceValues(forKeys: [.isPackageKey]))?.isPackage == true {
            return "package (see --skip-packages)"
        }
        // Desktop and Documents may be synced by iCloud Drive.
        if !options.allowCloud, path.range(of: #"^/Users/[^/]+/(?:Desktop|Documents)$"#, options: .regularExpression) != nil,
           (try? url.resourceValues(forKeys: [.isUbiquitousItemKey]))?.isUbiquitousItem == true {
            return "synced with iCloud Drive (see --allow-cloud)"
        }
        return nil
    }

    private func consider(_ path: String, _ stat: FileStat, sourceOnly: Bool) {
        report.files += 1
        report.bytes += stat.size
        guard stat.isRegularFile, stat.size > 0, stat.size >= options.minimumSize else { return }
        if stat.flags & UInt32(SF_DATALESS) != 0 { return skip(path, "not downloaded from cloud storage") }
        if stat.flags & UInt32(UF_COMPRESSED) != 0 { return skip(path, "compressed by the file system") }
        if stat.allocatedBytes < stat.size { return skip(path, "sparse") }
        guard seen.insert([UInt64(bitPattern: Int64(stat.device)), stat.inode]).inserted else {
            return skip(path, "already seen through another path")
        }
        files.append(ScannedFile(path: path, stat: stat, keepReason: keepReason(stat, sourceOnly: sourceOnly)))
    }

    /// Files treated as source-only: usable as a clone source, never replaced.
    private func keepReason(_ stat: FileStat, sourceOnly: Bool) -> String? {
        if sourceOnly { return "in a source-only folder" }
        if stat.linkCount > 1 { return "has \(stat.linkCount) hard links" }
        if stat.flags & UInt32(UF_APPEND | SF_APPEND) != 0 { return "append-only" }
        if stat.flags & UInt32(UF_IMMUTABLE | SF_IMMUTABLE) != 0 { return "locked" }
        if geteuid() != 0, stat.owner != geteuid() { return "owned by another user" }
        return nil
    }

    private func skip(_ path: String, _ reason: String) {
        report.skipped[reason, default: 0] += 1
        if options.verbose { log("skip \(path): \(reason)") }
    }

    // MARK: Grouping

    /// At least two files, and at least one of them can be replaced.
    private func worthComparing(_ files: [ScannedFile]) -> Bool {
        files.count > 1 && files.contains { $0.keepReason == nil }
    }

    private func blocker(_ file: ScannedFile) -> String? {
        if let reason = file.keepReason { return reason }
        let folder = (file.path as NSString).deletingLastPathComponent
        if writableFolders[folder] == nil { writableFolders[folder] = access(folder, W_OK) == 0 }
        return writableFolders[folder]! ? nil : "folder is not writable"
    }

    private func makeGroup(_ identical: [ScannedFile]) -> DuplicateGroup? {
        let files = identical.sorted { $0.path < $1.path }
        let infos = files.map { cloneInfo(path: $0.path) }

        // Families of files that already share all of their storage.
        var families: [[Int]] = []
        for index in files.indices {
            let family = families.firstIndex { family in
                guard let a = infos[family[0]], let b = infos[index], a.mayShareBlocks, b.mayShareBlocks,
                      a.cloneID != 0, a.cloneID == b.cloneID else { return false }
                return shareStorage(files[family[0]].path, files[index].path) == true
            }
            if let family { families[family].append(index) } else { families.append([index]) }
        }

        // Clone from the family whose storage stays in use anyway (it holds a file that can't be
        // replaced), otherwise from the largest family.
        let blockers = files.map(blocker)
        let sourceFamily = families.indices.max { lhs, rhs in
            let left = (families[lhs].contains { blockers[$0] != nil } ? 1 : 0, families[lhs].count)
            let right = (families[rhs].contains { blockers[$0] != nil } ? 1 : 0, families[rhs].count)
            return left < right
        }!
        let source = families[sourceFamily][0]

        var alreadyShared: [ScannedFile] = []
        var targetSets: [[ScannedFile]] = []
        var kept: [(file: ScannedFile, reason: String)] = []
        for (familyIndex, family) in families.enumerated() {
            if familyIndex == sourceFamily {
                alreadyShared += family.filter { $0 != source }.map { files[$0] }
            } else if family.allSatisfy({ blockers[$0] == nil }) {
                targetSets.append(family.map { files[$0] })
            } else {
                kept += family.map { (files[$0], blockers[$0] ?? "shares storage with a file that must stay") }
            }
        }
        return DuplicateGroup(source: files[source], alreadyShared: alreadyShared, targetSets: targetSets, kept: kept)
    }

    // MARK: Helpers

    private func status(_ message: String) {
        log(message)
    }

    private func digestWords(_ digest: SHA256.Digest) -> [UInt64] {
        digest.withUnsafeBytes { raw in (0..<4).map { raw.loadUnaligned(fromByteOffset: $0 * 8, as: UInt64.self) } }
    }

    /// Runs `transform` over `items` on all cores, keeping results in order.
    private func parallelMap<T>(_ items: [ScannedFile], total: Int64, cost: (ScannedFile) -> Int64,
                                _ transform: (ScannedFile) throws -> T) -> [Result<T, Error>] {
        let progress = ProgressLine(total: total)
        let results = UnsafeMutableBufferPointer<Result<T, Error>?>.allocate(capacity: items.count)
        results.initialize(repeating: nil)
        defer { results.deallocate() }
        DispatchQueue.concurrentPerform(iterations: items.count) { index in
            results[index] = Result { try transform(items[index]) }
            progress.advance(by: cost(items[index]))
        }
        progress.finish()
        return results.map { $0! }
    }
}

private extension Result {
    func value(recordingIssueIn report: inout ScanReport) -> Success? {
        switch self {
        case .success(let value):
            return value
        case .failure(let error):
            report.issues.append("\(error)")
            return nil
        }
    }
}

/// A single self-updating percentage on stderr, shown only on a terminal.
final class ProgressLine {
    private let total: Int64
    private let lock = NSLock()
    private var done: Int64 = 0
    private var lastDraw = Date.distantPast
    private let enabled = isatty(STDERR_FILENO) != 0

    init(total: Int64) {
        self.total = max(total, 1)
    }

    func advance(by amount: Int64) {
        guard enabled else { return }
        lock.lock()
        defer { lock.unlock() }
        done += amount
        let now = Date()
        guard now.timeIntervalSince(lastDraw) > 0.2 else { return }
        lastDraw = now
        fputs("\r  \(done * 100 / total)%\u{1B}[K", stderr)
    }

    func finish() {
        if enabled { fputs("\r\u{1B}[K", stderr) }
    }
}
