import CryptoKit
import Darwin
import Foundation

struct ToolError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }

    static func posix(_ operation: String, _ path: String, code: Int32 = errno) -> ToolError {
        ToolError("\(operation) \(path): \(String(cString: strerror(code)))")
    }
}

struct Timestamp: Equatable {
    let seconds: Int
    let nanoseconds: Int

    init(_ value: timespec) {
        seconds = value.tv_sec
        nanoseconds = value.tv_nsec
    }

    var value: timespec { timespec(tv_sec: seconds, tv_nsec: nanoseconds) }
}

/// The parts of stat(2) used to decide whether a file is still the one that was examined.
struct FileStat {
    let device: dev_t
    let inode: UInt64
    let mode: mode_t
    let linkCount: nlink_t
    let owner: uid_t
    let group: gid_t
    let flags: UInt32
    let size: Int64
    let blocks: Int64
    let accessed: Timestamp
    let modified: Timestamp
    let changed: Timestamp
    let created: Timestamp

    init(_ s: stat) {
        device = s.st_dev
        inode = s.st_ino
        mode = s.st_mode
        linkCount = s.st_nlink
        owner = s.st_uid
        group = s.st_gid
        flags = s.st_flags
        size = s.st_size
        blocks = s.st_blocks
        accessed = Timestamp(s.st_atimespec)
        modified = Timestamp(s.st_mtimespec)
        changed = Timestamp(s.st_ctimespec)
        created = Timestamp(s.st_birthtimespec)
    }

    var isRegularFile: Bool { mode & S_IFMT == S_IFREG }
    var allocatedBytes: Int64 { blocks * 512 }

    /// Same inode, and neither its contents nor its metadata changed.
    func isSameVersion(as other: FileStat) -> Bool {
        device == other.device && inode == other.inode && size == other.size
            && modified == other.modified && changed == other.changed
    }
}

func statPath(_ path: String) throws -> FileStat {
    var s = stat()
    guard lstat(path, &s) == 0 else { throw ToolError.posix("Cannot stat", path) }
    return FileStat(s)
}

func statDescriptor(_ fd: Int32, _ path: String) throws -> FileStat {
    var s = stat()
    guard fstat(fd, &s) == 0 else { throw ToolError.posix("Cannot stat", path) }
    return FileStat(s)
}

func openForReading(_ path: String) throws -> Int32 {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw ToolError.posix("Cannot open", path) }
    return fd
}

func isAPFS(_ path: String) throws -> Bool {
    var fs = statfs()
    guard statfs(path, &fs) == 0 else { throw ToolError.posix("Cannot inspect the volume of", path) }
    let name = withUnsafeBytes(of: fs.f_fstypename) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    return name == "apfs"
}

// MARK: - Content

/// Number of leading bytes hashed to quickly filter same-size candidates before reading full files.
let headerSize = 4096
let chunkSize = 1 << 20

struct Header {
    let digest: SHA256.Digest
    let isExecutable: Bool
}

/// Reads until the buffer is full or the file ends, retrying interrupted reads.
private func readFully(_ fd: Int32, into buffer: UnsafeMutableRawBufferPointer, at offset: Int64, path: String) throws -> Int {
    var total = 0
    while total < buffer.count {
        let n = pread(fd, buffer.baseAddress! + total, buffer.count - total, offset + Int64(total))
        if n < 0 {
            if errno == EINTR { continue }
            throw ToolError.posix("Cannot read", path)
        }
        if n == 0 { break }
        total += n
    }
    return total
}

func readHeader(_ path: String, size: Int64) throws -> Header {
    let fd = try openForReading(path)
    defer { close(fd) }
    _ = fcntl(fd, F_NOCACHE, 1)
    var bytes = [UInt8](repeating: 0, count: Int(min(size, Int64(headerSize))))
    let count = try bytes.withUnsafeMutableBytes { try readFully(fd, into: $0, at: 0, path: path) }
    guard count == bytes.count else { throw ToolError("\(path) changed size while being read") }
    return Header(digest: SHA256.hash(data: bytes), isExecutable: looksExecutable(bytes, path: path))
}

/// Detects Mach-O binaries (thin or fat, either byte order), static archives, and .dylib files.
func looksExecutable(_ header: [UInt8], path: String) -> Bool {
    if path.hasSuffix(".dylib") { return true }
    if header.starts(with: Array("!<arch>\n".utf8)) { return true }
    guard header.count >= 4 else { return false }
    let magic = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
    let machOMagics: Set<UInt32> = [
        0xfeed_face, 0xfeed_facf, 0xcefa_edfe, 0xcffa_edfe,  // MH_MAGIC(_64), MH_CIGAM(_64)
        0xcafe_babe, 0xbeba_feca, 0xcafe_babf, 0xbfba_feca,  // FAT_MAGIC(_64), FAT_CIGAM(_64)
    ]
    return machOMagics.contains(magic)
}

func contentDigest(_ path: String, size: Int64) throws -> SHA256.Digest {
    let fd = try openForReading(path)
    defer { close(fd) }
    _ = fcntl(fd, F_NOCACHE, 1)
    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: chunkSize, alignment: 16384)
    defer { buffer.deallocate() }
    var hasher = SHA256()
    var offset: Int64 = 0
    while true {
        let count = try readFully(fd, into: buffer, at: offset, path: path)
        hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: buffer[..<count]))
        offset += Int64(count)
        if count < buffer.count { break }
    }
    guard offset == size else { throw ToolError("\(path) changed size while being read") }
    return hasher.finalize()
}

/// Byte-for-byte comparison of two open files of the given size.
func sameContents(_ a: Int32, _ b: Int32, size: Int64, paths: (String, String)) throws -> Bool {
    let bufferA = UnsafeMutableRawBufferPointer.allocate(byteCount: chunkSize, alignment: 16384)
    let bufferB = UnsafeMutableRawBufferPointer.allocate(byteCount: chunkSize, alignment: 16384)
    defer {
        bufferA.deallocate()
        bufferB.deallocate()
    }
    var offset: Int64 = 0
    while offset < size {
        let wanted = Int(min(Int64(chunkSize), size - offset))
        let countA = try readFully(a, into: UnsafeMutableRawBufferPointer(rebasing: bufferA[..<wanted]), at: offset, path: paths.0)
        let countB = try readFully(b, into: UnsafeMutableRawBufferPointer(rebasing: bufferB[..<wanted]), at: offset, path: paths.1)
        guard countA == wanted, countB == wanted, memcmp(bufferA.baseAddress!, bufferB.baseAddress!, wanted) == 0 else {
            return false
        }
        offset += Int64(wanted)
    }
    return true
}

// MARK: - Clones

struct CloneInfo {
    let cloneID: UInt64
    let mayShareBlocks: Bool
}

func cloneInfo(path: String) -> CloneInfo? {
    cloneInfo { request, buffer, size in
        getattrlist(path, &request, buffer, size, UInt32(FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED))
    }
}

func cloneInfo(fd: Int32) -> CloneInfo? {
    cloneInfo { request, buffer, size in
        fgetattrlist(fd, &request, buffer, size, UInt32(FSOPT_ATTR_CMN_EXTENDED))
    }
}

/// Reads ATTR_CMNEXT_CLONEID and ATTR_CMNEXT_EXT_FLAGS for a file.
private func cloneInfo(_ query: (inout attrlist, UnsafeMutableRawPointer, Int) -> Int32) -> CloneInfo? {
    var request = attrlist()
    request.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
    request.commonattr = attrgroup_t(truncatingIfNeeded: ATTR_CMN_RETURNED_ATTRS)
    request.forkattr = attrgroup_t(truncatingIfNeeded: ATTR_CMNEXT_CLONEID | ATTR_CMNEXT_EXT_FLAGS)
    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 64, alignment: 8)
    defer { buffer.deallocate() }
    guard query(&request, buffer.baseAddress!, buffer.count) == 0 else { return nil }
    // Layout: u_int32_t length, attribute_set_t returned (forkattr is its fifth field), then values.
    let returned = buffer.loadUnaligned(fromByteOffset: 20, as: UInt32.self)
    var offset = 4 + MemoryLayout<attribute_set_t>.size
    guard returned & UInt32(ATTR_CMNEXT_CLONEID) != 0 else { return nil }
    let cloneID = buffer.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
    offset += 8
    var extendedFlags: UInt64 = 0
    if returned & UInt32(ATTR_CMNEXT_EXT_FLAGS) != 0 {
        extendedFlags = buffer.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
    }
    return CloneInfo(cloneID: cloneID, mayShareBlocks: extendedFlags & UInt64(EF_MAY_SHARE_BLOCKS) != 0)
}

/// Reports whether two distinct inodes share all of their physical storage: they must have the
/// same clone ID and map every logical offset to the same physical offset.
/// Returns nil when this cannot be determined, for example for compressed files.
func shareStorage(_ a: Int32, _ b: Int32) -> Bool? {
    var sa = stat()
    var sb = stat()
    guard fstat(a, &sa) == 0, fstat(b, &sb) == 0 else { return nil }
    guard sa.st_dev == sb.st_dev, sa.st_size == sb.st_size, sa.st_size > 0, sa.st_ino != sb.st_ino,
          sa.st_blocks == sb.st_blocks else { return false }
    if (sa.st_flags | sb.st_flags) & UInt32(UF_COMPRESSED) != 0 { return nil }
    guard let infoA = cloneInfo(fd: a), let infoB = cloneInfo(fd: b) else { return nil }
    guard infoA.mayShareBlocks, infoB.mayShareBlocks, infoA.cloneID != 0, infoA.cloneID == infoB.cloneID else {
        return false
    }
    return physicalExtentsMatch(a, b, size: sa.st_size)
}

func shareStorage(_ pathA: String, _ pathB: String) -> Bool? {
    guard let a = try? openForReading(pathA) else { return nil }
    defer { close(a) }
    guard let b = try? openForReading(pathB) else { return nil }
    defer { close(b) }
    return shareStorage(a, b)
}

private func physicalExtentsMatch(_ a: Int32, _ b: Int32, size: Int64) -> Bool? {
    var offset: Int64 = 0
    while offset < size {
        guard let extentA = physicalExtent(a, at: offset, length: size - offset),
              let extentB = physicalExtent(b, at: offset, length: size - offset) else { return nil }
        guard extentA.deviceOffset == extentB.deviceOffset else { return false }
        let step = min(extentA.length, extentB.length)
        guard step > 0 else { return nil }
        offset += step
    }
    return true
}

private func physicalExtent(_ fd: Int32, at offset: Int64, length: Int64) -> (deviceOffset: Int64, length: Int64)? {
    var query = log2phys()
    query.l2p_contigbytes = length
    query.l2p_devoffset = offset
    guard fcntl(fd, F_LOG2PHYS_EXT, &query) != -1 else { return nil }
    return (query.l2p_devoffset, query.l2p_contigbytes)
}

// MARK: - Extended attributes

let resourceForkName = "com.apple.ResourceFork"

/// Attributes that hold file content rather than metadata. A clone already carries the source's
/// copies, which are identical because resource forks are part of the content comparison.
private let contentAttributes: Set<String> = [resourceForkName, "com.apple.decmpfs"]

/// Attributes the kernel may refuse to change. Failing to reproduce them is reported, not fatal.
private let restrictedAttributes: Set<String> = ["com.apple.macl", "com.apple.provenance"]

func listAttributes(_ path: String) throws -> [String] {
    while true {
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size >= 0 else { throw ToolError.posix("Cannot list extended attributes of", path) }
        if size == 0 { return [] }
        var names = [UInt8](repeating: 0, count: size)
        let count = listxattr(path, &names, size, XATTR_NOFOLLOW)
        if count < 0 {
            if errno == ERANGE { continue }
            throw ToolError.posix("Cannot list extended attributes of", path)
        }
        return names[..<count].split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
    }
}

/// The attribute's value, or nil when the file doesn't have it.
func readAttribute(_ path: String, _ name: String) throws -> [UInt8]? {
    try readAttribute(name, path) { getxattr(path, name, $0, $1, 0, XATTR_NOFOLLOW) }
}

func readAttribute(fd: Int32, _ name: String, path: String) throws -> [UInt8]? {
    try readAttribute(name, path) { fgetxattr(fd, name, $0, $1, 0, 0) }
}

private func readAttribute(_ name: String, _ path: String, _ get: (UnsafeMutableRawPointer?, Int) -> Int) throws -> [UInt8]? {
    while true {
        let size = get(nil, 0)
        if size < 0 {
            if errno == ENOATTR { return nil }
            throw ToolError.posix("Cannot read \(name) of", path)
        }
        var value = [UInt8](repeating: 0, count: size)
        let count = value.withUnsafeMutableBytes { get($0.baseAddress, size) }
        if count < 0 {
            if errno == ERANGE { continue }
            if errno == ENOATTR { return nil }
            throw ToolError.posix("Cannot read \(name) of", path)
        }
        return Array(value[..<count])
    }
}

// MARK: - Metadata

/// Gives the clone at `clone` the metadata of `original`: extended attributes, mode, owner, flags,
/// and access, modification, creation and date-added times. ACLs are handled separately, because
/// a deny-delete entry would block the swap.
func copyMetadata(from original: String, to clone: String, warn: (String) -> Void) throws {
    let wanted = Set(try listAttributes(original)).subtracting(contentAttributes)
    let present = Set(try listAttributes(clone)).subtracting(contentAttributes)
    for name in present.subtracting(wanted).sorted() where removexattr(clone, name, XATTR_NOFOLLOW) != 0 {
        let error = ToolError.posix("Cannot remove \(name) from", clone)
        guard restrictedAttributes.contains(name) else { throw error }
        warn(error.description)
    }
    for name in wanted.sorted() {
        guard let value = try readAttribute(original, name), try readAttribute(clone, name) != value else { continue }
        let result = value.withUnsafeBytes { setxattr(clone, name, $0.baseAddress, $0.count, 0, XATTR_NOFOLLOW) }
        if result != 0 {
            let error = ToolError.posix("Cannot set \(name) on", clone)
            guard restrictedAttributes.contains(name) else { throw error }
            warn(error.description)
        }
    }

    let flags = copyfile_flags_t(COPYFILE_STAT | COPYFILE_NOFOLLOW)
    guard copyfile(original, clone, nil, flags) == 0 else { throw ToolError.posix("Cannot copy metadata to", clone) }
    try copyDates(from: original, to: clone, warn: warn)
}

/// A file's extended ACL, owned until deinit.
final class AccessControlList {
    let acl: acl_t

    /// Nil when the file has no ACL.
    init?(fd: Int32) {
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else { return nil }
        self.acl = acl
    }

    deinit {
        acl_free(UnsafeMutableRawPointer(acl))
    }
}

/// Replaces the file's ACL; nil removes it.
func setAccessControlList(_ list: AccessControlList?, fd: Int32, path: String) throws {
    let acl = list?.acl ?? acl_init(0)!
    defer { if list == nil { acl_free(UnsafeMutableRawPointer(acl)) } }
    guard acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0 else { throw ToolError.posix("Cannot set the ACL of", path) }
}

/// The file's ACL as text, or nil when it has none.
func accessControlList(_ path: String) -> String? {
    guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return nil }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var length = 0
    guard let text = acl_to_text(acl, &length) else { return nil }
    defer { acl_free(UnsafeMutableRawPointer(text)) }
    let value = String(cString: text)
    return value.split(separator: "\n").count > 1 ? value : nil
}

/// Copies the creation and date-added times, which copyfile() doesn't carry.
private func copyDates(from original: String, to clone: String, warn: (String) -> Void) throws {
    var request = attrlist()
    request.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
    request.commonattr = attrgroup_t(truncatingIfNeeded: ATTR_CMN_RETURNED_ATTRS) | attrgroup_t(ATTR_CMN_CRTIME | ATTR_CMN_ADDEDTIME)
    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 128, alignment: 8)
    defer { buffer.deallocate() }
    guard getattrlist(original, &request, buffer.baseAddress, buffer.count, UInt32(FSOPT_NOFOLLOW)) == 0 else {
        throw ToolError.posix("Cannot read dates of", original)
    }
    let returned = buffer.loadUnaligned(fromByteOffset: 4, as: UInt32.self)
    var offset = 4 + MemoryLayout<attribute_set_t>.size
    var dates: [timespec] = []
    var attributes: attrgroup_t = 0
    for attribute in [ATTR_CMN_CRTIME, ATTR_CMN_ADDEDTIME] where returned & UInt32(attribute) != 0 {
        dates.append(buffer.loadUnaligned(fromByteOffset: offset, as: timespec.self))
        offset += MemoryLayout<timespec>.size
        attributes |= attrgroup_t(attribute)
    }
    guard !dates.isEmpty else { return }

    request.commonattr = attributes
    let result = dates.withUnsafeMutableBytes { setattrlist(clone, &request, $0.baseAddress, $0.count, UInt32(FSOPT_NOFOLLOW)) }
    guard result != 0 else { return }
    // Fall back to the creation time alone if the date added can't be set.
    guard attributes & attrgroup_t(ATTR_CMN_CRTIME) != 0 else { return }
    warn(ToolError.posix("Cannot set the date added of", clone).description)
    request.commonattr = attrgroup_t(ATTR_CMN_CRTIME)
    var created = dates[0]
    guard setattrlist(clone, &request, &created, MemoryLayout<timespec>.size, UInt32(FSOPT_NOFOLLOW)) == 0 else {
        throw ToolError.posix("Cannot set the creation date of", clone)
    }
}

func restoreTimes(of path: String, from saved: FileStat) {
    var times = [saved.accessed.value, saved.modified.value]
    _ = utimensat(AT_FDCWD, path, &times, AT_SYMLINK_NOFOLLOW)
}
