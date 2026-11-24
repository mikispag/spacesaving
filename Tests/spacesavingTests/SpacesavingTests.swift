import Darwin
import Foundation
import XCTest
@testable import SpacesavingCore

final class SpacesavingTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        let base = FileManager.default.temporaryDirectory
        let rawDir = base.appendingPathComponent("spacesaving-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: rawDir, withIntermediateDirectories: true)
        guard let resolved = realpath(rawDir.path, nil) else {
            throw ToolError.posix("Cannot resolve", rawDir.path)
        }
        defer { free(resolved) }
        tempDir = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
    }

    override func tearDownWithError() throws {
        if let tempDir {
            try? FileManager.default.removeItem(at: tempDir)
        }
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    private func makePayload(size: Int, seed: UInt8) -> Data {
        var bytes = [UInt8](repeating: 0, count: size)
        var state = UInt64(seed) &+ 0x9E37_79B9_7F4A_7C15
        for i in 0..<size {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            bytes[i] = UInt8(truncatingIfNeeded: state >> 56) | 1
        }
        return Data(bytes)
    }

    @discardableResult
    private func writeFile(_ relativePath: String, data: Data) throws -> URL {
        let url = tempDir.appendingPathComponent(relativePath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url)
        return url
    }

    private func setXattr(_ name: String, value: Data, on path: String) throws {
        let result = value.withUnsafeBytes { setxattr(path, name, $0.baseAddress, $0.count, 0, XATTR_NOFOLLOW) }
        XCTAssertEqual(result, 0, "setxattr failed: \(String(cString: strerror(errno)))")
    }

    private func setTimes(accessed: Int, modified: Int, on path: String) {
        var times = [timespec(tv_sec: accessed, tv_nsec: 0), timespec(tv_sec: modified, tv_nsec: 0)]
        XCTAssertEqual(utimensat(AT_FDCWD, path, &times, AT_SYMLINK_NOFOLLOW), 0)
    }

    // MARK: - Unit Tests

    func testParseSize() {
        XCTAssertEqual(parseSize("0"), 0)
        XCTAssertEqual(parseSize("512"), 512)
        XCTAssertEqual(parseSize("512B"), 512)
        XCTAssertEqual(parseSize("64K"), 64 * 1024)
        XCTAssertEqual(parseSize("64kb"), 64 * 1024)
        XCTAssertEqual(parseSize("1.5M"), 1_572_864)
        XCTAssertEqual(parseSize("2G"), 2 * 1024 * 1024 * 1024)
        XCTAssertEqual(parseSize("1T"), 1_099_511_627_776)

        XCTAssertNil(parseSize(""))
        XCTAssertNil(parseSize("-1"))
        XCTAssertNil(parseSize("abc"))
        XCTAssertNil(parseSize("10X"))
    }

    func testParseArguments() throws {
        let scan = try parseArguments([
            "scan", "-s", "/src", "--min-size", "128K", "-x", "node_modules",
            "--skip-packages", "--include-executables", "--allow-library",
            "--allow-cloud", "--allow-photos", "-l", "-v", "--", "-weird-dir",
        ])
        XCTAssertEqual(scan.command, "scan")
        XCTAssertEqual(scan.scan.sourceRoots, ["/src"])
        XCTAssertEqual(scan.scan.minimumSize, 128 * 1024)
        XCTAssertEqual(scan.scan.excludePatterns, ["node_modules"])
        XCTAssertFalse(scan.scan.scanPackages)
        XCTAssertTrue(scan.scan.includeExecutables)
        XCTAssertTrue(scan.scan.allowLibrary)
        XCTAssertTrue(scan.scan.allowCloud)
        XCTAssertTrue(scan.scan.allowPhotos)
        XCTAssertTrue(scan.list)
        XCTAssertTrue(scan.scan.verbose)
        XCTAssertEqual(scan.scan.roots, ["-weird-dir"])

        let reclaim = try parseArguments(["reclaim", "--delete", "--yes", "/tmp/a"])
        XCTAssertEqual(reclaim.command, "reclaim")
        XCTAssertFalse(reclaim.reclaim.useTrash)
        XCTAssertTrue(reclaim.assumeYes)
        XCTAssertEqual(reclaim.scan.roots, ["/tmp/a"])

        let check = try parseArguments(["check", "a.bin", "b.bin"])
        XCTAssertEqual(check.command, "check")
        XCTAssertEqual(check.files, ["a.bin", "b.bin"])

        XCTAssertThrowsError(try parseArguments(["check", "only-one"]))
        XCTAssertThrowsError(try parseArguments(["scan"]))
        XCTAssertThrowsError(try parseArguments(["unknown", "/tmp"]))
        XCTAssertThrowsError(try parseArguments(["scan", "--unknown", "/tmp"]))
        XCTAssertThrowsError(try parseArguments(["scan", "-m"]))
        XCTAssertThrowsError(try parseArguments(["--help"])) { error in
            XCTAssertEqual((error as? ToolError)?.description, usage)
        }
    }

    func testLooksExecutable() {
        XCTAssertTrue(looksExecutable([0xCF, 0xFA, 0xED, 0xFE, 0x00], path: "/tmp/tool"))
        XCTAssertTrue(looksExecutable([0xFE, 0xED, 0xFA, 0xCF, 0x00], path: "/tmp/tool"))
        XCTAssertTrue(looksExecutable([0xCA, 0xFE, 0xBA, 0xBE, 0x00], path: "/tmp/universal"))
        XCTAssertTrue(looksExecutable(Array("!<arch>\nrest".utf8), path: "/tmp/libfoo.a"))
        XCTAssertTrue(looksExecutable([0x01, 0x02, 0x03, 0x04], path: "/tmp/libfoo.dylib"))

        XCTAssertFalse(looksExecutable(Array("Hello, world!".utf8), path: "/tmp/readme.txt"))
        XCTAssertFalse(looksExecutable([0x01, 0x02], path: "/tmp/tiny.bin"))
    }

    // MARK: - APFS Integration Tests

    func testScanAndReclaimDuplicatesOnAPFS() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 42)
        let otherPayload = makePayload(size: 128 * 1024, seed: 99)
        var sameHeaderDifferentTail = payload
        sameHeaderDifferentTail[sameHeaderDifferentTail.count - 1] ^= 0xFF
        let smallPayload = makePayload(size: 4096, seed: 7)

        let a = try writeFile("a.bin", data: payload)
        let b = try writeFile("b.bin", data: payload)
        let c = try writeFile("sub/c.bin", data: payload)
        _ = try writeFile("different.bin", data: otherPayload)
        _ = try writeFile("same-header.bin", data: sameHeaderDifferentTail)
        _ = try writeFile("small1.bin", data: smallPayload)
        _ = try writeFile("small2.bin", data: smallPayload)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.path]
        let report = try Scanner(options: scanOptions, log: { _ in }).scan()

        XCTAssertEqual(report.replaceableGroups.count, 1)
        let group = try XCTUnwrap(report.replaceableGroups.first)
        XCTAssertEqual(group.targets.count, 2)
        XCTAssertGreaterThan(report.reclaimableBytes, 0)
        XCTAssertEqual(shareStorage(a.path, b.path), false)

        var reclaimOptions = ReclaimOptions()
        reclaimOptions.useTrash = false
        let summary = Reclaimer(options: reclaimOptions, log: { _ in }).run(report.replaceableGroups) { false }

        XCTAssertEqual(summary.replaced, 2)
        XCTAssertTrue(summary.failed.isEmpty)
        XCTAssertTrue(summary.skipped.isEmpty)
        XCTAssertNil(summary.stopReason)
        XCTAssertGreaterThan(summary.freedBytes, 0)

        XCTAssertEqual(shareStorage(a.path, b.path), true)
        XCTAssertEqual(shareStorage(a.path, c.path), true)
        XCTAssertNotEqual(try statPath(a.path).inode, try statPath(b.path).inode)
        XCTAssertEqual(try Data(contentsOf: a), payload)
        XCTAssertEqual(try Data(contentsOf: b), payload)
        XCTAssertEqual(try Data(contentsOf: c), payload)

        // Second scan should find nothing left to replace and report 2 already-shared clones.
        let secondReport = try Scanner(options: scanOptions, log: { _ in }).scan()
        XCTAssertTrue(secondReport.replaceableGroups.isEmpty)
        XCTAssertEqual(secondReport.groups.count, 1)
        XCTAssertEqual(secondReport.groups[0].alreadyShared.count, 2)

        // CLI check and help exit cleanly.
        XCTAssertEqual(runCLI(arguments: ["--help"]), 0)
        XCTAssertEqual(runCLI(arguments: ["check", a.path, b.path]), 0)
    }

    func testMetadataAndParentFolderTimesPreserved() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 12)
        let source = try writeFile("a-source.bin", data: payload)
        let targetDir = tempDir.appendingPathComponent("target-dir", isDirectory: true)
        let target = try writeFile("target-dir/z-target.bin", data: payload)

        try setXattr("com.example.source-only", value: Data("drop-me".utf8), on: source.path)
        try setXattr("com.example.target-keep", value: Data("keep-me".utf8), on: target.path)
        XCTAssertEqual(chmod(target.path, 0o640), 0)

        let targetMtime = 1_700_000_000
        let folderMtime = 1_650_000_000
        setTimes(accessed: targetMtime, modified: targetMtime, on: target.path)
        setTimes(accessed: folderMtime, modified: folderMtime, on: targetDir.path)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.path]
        let report = try Scanner(options: scanOptions, log: { _ in }).scan()
        XCTAssertEqual(report.replaceableGroups.count, 1)

        var reclaimOptions = ReclaimOptions()
        reclaimOptions.useTrash = false
        let summary = Reclaimer(options: reclaimOptions, log: { _ in }).run(report.replaceableGroups) { false }
        XCTAssertEqual(summary.replaced, 1)
        XCTAssertTrue(summary.failed.isEmpty)

        XCTAssertEqual(shareStorage(source.path, target.path), true)
        let targetStat = try statPath(target.path)
        XCTAssertEqual(targetStat.mode & 0o777, 0o640)
        XCTAssertEqual(targetStat.modified.seconds, targetMtime)
        XCTAssertEqual(try readAttribute(target.path, "com.example.target-keep"), Array("keep-me".utf8))
        XCTAssertNil(try readAttribute(target.path, "com.example.source-only"))
        XCTAssertEqual(try statPath(targetDir.path).modified.seconds, folderMtime)
    }

    func testResourceForkComparisonAndPreservation() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 23)
        let f1 = try writeFile("r1.bin", data: payload)
        let f2 = try writeFile("r2.bin", data: payload)
        let f3 = try writeFile("r3.bin", data: payload)

        try setXattr(resourceForkName, value: Data("fork-A".utf8), on: f1.path)
        try setXattr(resourceForkName, value: Data("fork-A".utf8), on: f2.path)
        try setXattr(resourceForkName, value: Data("fork-B".utf8), on: f3.path)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.path]
        let report = try Scanner(options: scanOptions, log: { _ in }).scan()

        XCTAssertEqual(report.replaceableGroups.count, 1)
        let group = try XCTUnwrap(report.replaceableGroups.first)
        XCTAssertEqual(group.fileCount, 2)
        let groupPaths = Set(([group.source] + group.targets).map(\.path))
        XCTAssertFalse(groupPaths.contains(f3.path))

        var reclaimOptions = ReclaimOptions()
        reclaimOptions.useTrash = false
        let summary = Reclaimer(options: reclaimOptions, log: { _ in }).run(report.replaceableGroups) { false }
        XCTAssertEqual(summary.replaced, 1)
        XCTAssertEqual(shareStorage(f1.path, f2.path), true)
        XCTAssertEqual(try readAttribute(f2.path, resourceForkName), Array("fork-A".utf8))
    }

    func testSourceOnlyHardLinksAndLockedFiles() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload1 = makePayload(size: 128 * 1024, seed: 31)
        let srcFile = try writeFile("sources/ref.bin", data: payload1)
        let dstFile = try writeFile("work/copy.bin", data: payload1)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.appendingPathComponent("work").path]
        scanOptions.sourceRoots = [tempDir.appendingPathComponent("sources").path]
        let report1 = try Scanner(options: scanOptions, log: { _ in }).scan()
        XCTAssertEqual(report1.replaceableGroups.count, 1)
        XCTAssertEqual(report1.replaceableGroups[0].source.path, srcFile.path)
        XCTAssertEqual(report1.replaceableGroups[0].targets.map(\.path), [dstFile.path])

        // Hard-linked file stays as source-only.
        let payload2 = makePayload(size: 128 * 1024, seed: 32)
        let hardOrig = try writeFile("hard/orig.bin", data: payload2)
        let hardLink = tempDir.appendingPathComponent("hard/link.bin")
        XCTAssertEqual(link(hardOrig.path, hardLink.path), 0)
        let independent = try writeFile("hard/aaa-copy.bin", data: payload2)

        var hardOptions = ScanOptions()
        hardOptions.roots = [tempDir.appendingPathComponent("hard").path]
        let report2 = try Scanner(options: hardOptions, log: { _ in }).scan()
        XCTAssertEqual(report2.replaceableGroups.count, 1)
        XCTAssertEqual(report2.replaceableGroups[0].targets.map(\.path), [independent.path])

        // Locked (UF_IMMUTABLE) file stays as source-only.
        let payload3 = makePayload(size: 128 * 1024, seed: 33)
        let locked = try writeFile("locked/z-locked.bin", data: payload3)
        let unlocked = try writeFile("locked/a-unlocked.bin", data: payload3)
        XCTAssertEqual(chflags(locked.path, UInt32(UF_IMMUTABLE)), 0)
        defer { _ = chflags(locked.path, 0) }

        var lockedOptions = ScanOptions()
        lockedOptions.roots = [tempDir.appendingPathComponent("locked").path]
        let report3 = try Scanner(options: lockedOptions, log: { _ in }).scan()
        XCTAssertEqual(report3.replaceableGroups.count, 1)
        XCTAssertEqual(report3.replaceableGroups[0].source.path, locked.path)
        XCTAssertEqual(report3.replaceableGroups[0].targets.map(\.path), [unlocked.path])
    }

    func testExclusionsAndExecutables() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 55)
        _ = try writeFile("excluded/a.bin", data: payload)
        _ = try writeFile("excluded/b.bin", data: payload)
        _ = try writeFile("Demo.photoslibrary/a.bin", data: payload)
        _ = try writeFile("Demo.photoslibrary/b.bin", data: payload)

        var machOPayload = makePayload(size: 128 * 1024, seed: 56)
        machOPayload[0] = 0xCF
        machOPayload[1] = 0xFA
        machOPayload[2] = 0xED
        machOPayload[3] = 0xFE
        _ = try writeFile("bin1", data: machOPayload)
        _ = try writeFile("bin2", data: machOPayload)

        var defaultOptions = ScanOptions()
        defaultOptions.roots = [tempDir.path]
        defaultOptions.excludePatterns = ["/excluded$"]
        let defaultReport = try Scanner(options: defaultOptions, log: { _ in }).scan()
        XCTAssertTrue(defaultReport.replaceableGroups.isEmpty)

        var permissiveOptions = defaultOptions
        permissiveOptions.allowPhotos = true
        permissiveOptions.includeExecutables = true
        let permissiveReport = try Scanner(options: permissiveOptions, log: { _ in }).scan()
        XCTAssertEqual(permissiveReport.replaceableGroups.count, 2)
    }

    func testTargetModifiedAfterScanIsSkipped() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 77)
        _ = try writeFile("a.bin", data: payload)
        let target = try writeFile("b.bin", data: payload)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.path]
        let report = try Scanner(options: scanOptions, log: { _ in }).scan()
        XCTAssertEqual(report.replaceableGroups.count, 1)

        // Mutate the target after scanning.
        var modified = payload
        modified[100] ^= 0xAA
        try modified.write(to: target)

        var reclaimOptions = ReclaimOptions()
        reclaimOptions.useTrash = false
        let summary = Reclaimer(options: reclaimOptions, log: { _ in }).run(report.replaceableGroups) { false }

        XCTAssertEqual(summary.replaced, 0)
        XCTAssertEqual(summary.skipped.count, 1)
        XCTAssertEqual(try Data(contentsOf: target), modified)
    }

    func testAlreadyClonedFilesAreRecognized() throws {
        try XCTSkipUnless(try isAPFS(tempDir.path), "Requires an APFS volume")

        let payload = makePayload(size: 128 * 1024, seed: 88)
        let orig = try writeFile("orig.bin", data: payload)
        let cloned = tempDir.appendingPathComponent("cloned.bin")
        XCTAssertEqual(clonefile(orig.path, cloned.path, 0), 0)

        XCTAssertEqual(shareStorage(orig.path, cloned.path), true)

        var scanOptions = ScanOptions()
        scanOptions.roots = [tempDir.path]
        let report = try Scanner(options: scanOptions, log: { _ in }).scan()
        XCTAssertTrue(report.replaceableGroups.isEmpty)
        XCTAssertEqual(report.groups.count, 1)
        XCTAssertEqual(report.groups[0].alreadyShared.count, 1)
    }
}
