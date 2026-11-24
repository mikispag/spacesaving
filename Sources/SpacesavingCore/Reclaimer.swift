import Darwin
import Foundation

struct ReclaimOptions {
    var useTrash = true
    var verbose = false
}

struct ReclaimSummary {
    var replaced = 0
    var freedBytes: Int64 = 0
    var skipped: [(path: String, reason: String)] = []
    var failed: [(path: String, reason: String)] = []
    var warnings: [String] = []
    /// Set when the run ended early: interrupted, or a state that needs a person to look at it.
    var stopReason: String?
}

/// A failure that leaves files in a state that needs attention, so no further files are touched.
private struct Showstopper: Error, CustomStringConvertible {
    let description: String
}

private struct TemporaryClone {
    let path: String
    let inode: UInt64
}

private enum Outcome {
    case replaced
    case skipped(String)
}

/// Replaces each target with a clone of its group's source: claim and recheck the target, clone
/// the source next to it, verify the clone, copy the target's metadata, swap the two atomically,
/// then dispose of the original.
final class Reclaimer {
    private let options: ReclaimOptions
    private let log: (String) -> Void
    private var summary = ReclaimSummary()

    init(options: ReclaimOptions, log: @escaping (String) -> Void) {
        self.options = options
        self.log = log
    }

    func run(_ groups: [DuplicateGroup], shouldStop: () -> Bool) -> ReclaimSummary {
        for group in groups {
            for set in group.targetSets {
                var replacedAll = true
                for target in set {
                    if shouldStop() {
                        summary.stopReason = "Interrupted."
                        return summary
                    }
                    do {
                        switch try replace(target, with: group.source) {
                        case .replaced:
                            summary.replaced += 1
                            if options.verbose { log("cloned \(group.source.path) -> \(target.path)") }
                        case .skipped(let reason):
                            replacedAll = false
                            summary.skipped.append((target.path, reason))
                            if options.verbose { log("skip \(target.path): \(reason)") }
                        }
                    } catch let error as Showstopper {
                        summary.failed.append((target.path, error.description))
                        summary.stopReason = "Stopped after an error that needs attention."
                        return summary
                    } catch {
                        replacedAll = false
                        summary.failed.append((target.path, "\(error)"))
                        log("error \(target.path): \(error)")
                    }
                }
                if replacedAll { summary.freedBytes += group.reclaimableBytes(of: set) }
            }
        }
        return summary
    }

    private func replace(_ target: ScannedFile, with source: ScannedFile) throws -> Outcome {
        // Claim the target and make sure it is still the file that was scanned.
        let targetFD = try openForReading(target.path)
        defer { close(targetFD) }
        let original = try statDescriptor(targetFD, target.path)
        guard original.isSameVersion(as: target.stat) else { return .skipped("changed since the scan") }
        guard original.linkCount == 1, original.flags & UInt32(UF_IMMUTABLE | SF_IMMUTABLE | UF_APPEND | SF_APPEND) == 0 else {
            return .skipped("gained hard links or flags since the scan")
        }

        let sourceFD = try openForReading(source.path)
        defer { close(sourceFD) }
        let sourceStat = try statDescriptor(sourceFD, source.path)
        guard sourceStat.device == original.device, sourceStat.size == original.size else {
            return .skipped("source \(source.path) changed since the scan")
        }
        if shareStorage(sourceFD, targetFD) == true { return .skipped("already shares storage with the source") }

        let folder = (target.path as NSString).deletingLastPathComponent
        let folderStat = try statPath(folder)
        defer { restoreTimes(of: folder, from: folderStat) }

        // Clone the source next to the target.
        let clone = try makeClone(of: sourceFD, besides: target.path)
        do {
            let outcome = try install(clone, as: target, targetFD: targetFD, original: original, sourceFD: sourceFD)
            if case .skipped = outcome, let problem = discard(clone) { throw Showstopper(description: problem) }
            return outcome
        } catch let error as Showstopper {
            throw error
        } catch {
            if let problem = discard(clone) { throw Showstopper(description: "\(error). \(problem)") }
            throw error
        }
    }

    /// Verifies the clone, gives it the target's metadata, swaps it into the target's place and
    /// disposes of the original.
    private func install(_ clone: TemporaryClone, as target: ScannedFile, targetFD: Int32, original: FileStat,
                         sourceFD: Int32) throws -> Outcome {
        let cloneFD = try openForReading(clone.path)
        defer { close(cloneFD) }
        // Drop any ACL inherited from the source, so the clone can always be renamed and removed.
        try setAccessControlList(nil, fd: cloneFD, path: clone.path)

        // The clone must hold exactly the target's bytes. Comparing the clone rather than the
        // source also covers changes made to the source between the scan and the clone.
        guard try sameContents(cloneFD, targetFD, size: original.size, paths: (clone.path, target.path)),
              try readAttribute(fd: cloneFD, resourceForkName, path: clone.path)
              == readAttribute(fd: targetFD, resourceForkName, path: target.path) else {
            return .skipped("contents no longer match the source")
        }
        if shareStorage(cloneFD, sourceFD) == false { return .skipped("the clone does not share storage with the source") }

        try copyMetadata(from: target.path, to: clone.path) { summary.warnings.append($0) }
        let prepared = try statDescriptor(cloneFD, clone.path)
        guard prepared.mode == original.mode, prepared.owner == original.owner, prepared.group == original.group,
              prepared.flags == original.flags, prepared.modified == original.modified, prepared.created == original.created else {
            return .skipped("its metadata could not be reproduced on the clone")
        }

        // Last check: the target must not have changed since it was compared.
        guard try statPath(target.path).isSameVersion(as: original) else { return .skipped("changed during replacement") }

        // A deny-delete entry in the target's ACL would block the swap, so the ACL is lifted until
        // the clone is in place, then given to the clone.
        let originalACL = AccessControlList(fd: targetFD)
        let originalACLText = accessControlList(target.path)
        func restoreOriginalACL() -> String? {
            guard let originalACL else { return nil }
            do {
                try setAccessControlList(originalACL, fd: targetFD, path: target.path)
                return nil
            } catch {
                return "Could not restore the original's ACL: \(error)"
            }
        }
        if originalACL != nil { try setAccessControlList(nil, fd: targetFD, path: target.path) }

        guard renamex_np(clone.path, target.path, UInt32(RENAME_SWAP)) == 0 else {
            let error = ToolError.posix("Cannot swap in the clone for", target.path)
            if let problem = restoreOriginalACL() { throw Showstopper(description: "\(error). \(problem)") }
            throw error
        }
        // The original now sits at the temporary path.
        do {
            guard (try? statPath(target.path))?.inode == clone.inode, (try? statPath(clone.path))?.inode == original.inode else {
                throw ToolError("Could not verify the swap")
            }
            try setAccessControlList(originalACL, fd: cloneFD, path: target.path)
            guard accessControlList(target.path) == originalACLText else { throw ToolError("The ACL did not carry over to the clone") }
        } catch {
            try? setAccessControlList(nil, fd: cloneFD, path: target.path)
            guard renamex_np(clone.path, target.path, UInt32(RENAME_SWAP)) == 0, (try? statPath(target.path))?.inode == original.inode else {
                throw Showstopper(description: "\(error), and the original could not be put back. Check \(target.path) and \(clone.path)")
            }
            if let problem = restoreOriginalACL() { throw Showstopper(description: "\(error). \(problem)") }
            throw ToolError("\(error); the original was put back")
        }

        do {
            if options.useTrash {
                try FileManager.default.trashItem(at: URL(fileURLWithPath: clone.path), resultingItemURL: nil)
            } else if unlink(clone.path) != 0 {
                throw ToolError.posix("Cannot delete", clone.path)
            }
        } catch {
            let problem = restoreOriginalACL().map { " \($0)" } ?? ""
            throw Showstopper(description: "Replaced, but the original could not be removed from \(clone.path): \(error).\(problem)")
        }
        // Keep the original intact in the Trash, in case it is put back.
        if options.useTrash, let problem = restoreOriginalACL() { summary.warnings.append("\(target.path): \(problem)") }
        return .replaced
    }

    /// Removes the clone if it is still at its temporary path, returning a problem if that fails.
    private func discard(_ clone: TemporaryClone) -> String? {
        guard (try? statPath(clone.path))?.inode == clone.inode, unlink(clone.path) != 0 else { return nil }
        return ToolError.posix("Could not remove the temporary clone", clone.path).description
    }

    /// Clones the source into the target's folder under a temporary name, with fclonefileat(2).
    private func makeClone(of sourceFD: Int32, besides targetPath: String) throws -> TemporaryClone {
        let folder = (targetPath as NSString).deletingLastPathComponent
        let name = (targetPath as NSString).lastPathComponent
        for attempt in 0..<100 {
            let path = (folder as NSString).appendingPathComponent(temporaryName(for: name, attempt: attempt))
            if fclonefileat(sourceFD, AT_FDCWD, path, 0) == 0 { return TemporaryClone(path: path, inode: try statPath(path).inode) }
            guard errno == EEXIST else { throw ToolError.posix("Cannot create a clone at", path) }
        }
        throw ToolError("Ran out of temporary names next to \(targetPath)")
    }

    /// "name (spacesaving PID).ext", shortened to fit the 255-byte name limit. After the swap this
    /// is the original's name, so it stays recognizable in the Trash.
    private func temporaryName(for name: String, attempt: Int) -> String {
        var stem = name
        var fileExtension = ""
        if let dot = name.lastIndex(of: "."), dot != name.startIndex, name.distance(from: dot, to: name.endIndex) <= 32 {
            stem = String(name[..<dot])
            fileExtension = String(name[dot...])
        }
        let suffix = " (spacesaving \(getpid())\(attempt > 0 ? "-\(attempt)" : ""))" + fileExtension
        while !stem.isEmpty, stem.utf8.count + suffix.utf8.count > Int(NAME_MAX) {
            stem.removeLast()
        }
        return stem + suffix
    }
}
