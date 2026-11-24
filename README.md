# spacesaving

[![CI](https://github.com/mikispag/spacesaving/actions/workflows/ci.yml/badge.svg)](https://github.com/mikispag/spacesaving/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast, zero-dependency macOS command-line tool that reclaims disk space on APFS volumes by replacing identical files with copy-on-write APFS clones.

Cloned files share their underlying data blocks, so each set of identical files occupies the disk space of a single copy. Every file retains its own path, inode, permissions, timestamps, extended attributes, and ACLs, and future writes to one file are transparently copy-on-write isolated from the others.

## Requirements

- macOS 14 (Sonoma) or later
- An APFS volume
- Swift 6.0+ (to build from source)

## Installation

Build a release binary with Swift Package Manager and place it somewhere on your `PATH`:

```sh
git clone https://github.com/mikispag/spacesaving.git
cd spacesaving
swift build -c release
cp .build/release/spacesaving /usr/local/bin/spacesaving
```

## Usage

```sh
# Report identical files and estimated reclaimable space without changing anything
spacesaving scan --list ~/Downloads ~/Projects

# Replace identical files with APFS clones (prompts for confirmation; originals go to Trash)
spacesaving reclaim ~/Downloads ~/Projects

# Non-interactive reclaim, deleting replaced originals immediately
spacesaving reclaim --delete --yes ~/Downloads ~/Projects

# Check whether two files have identical contents and already share APFS storage
spacesaving check a.bin b.bin
```

### Commands

| Command | Description |
| --- | --- |
| `spacesaving scan [options] <folder>...` | Scan folders and report identical files and reclaimable space |
| `spacesaving reclaim [options] <folder>...` | Replace identical files with APFS clones of one another |
| `spacesaving check <file> <file>` | Inspect two files and report whether they already share storage |

### Options

| Option | Effect |
| --- | --- |
| `-s, --source <folder>` | Use files in `<folder>` as clone sources without ever modifying them (repeatable) |
| `-m, --min-size <size>` | Ignore files smaller than `<size>`, e.g. `4K`, `1M`, `2G` (default `64K`) |
| `-x, --exclude <regex>` | Skip folders whose path matches `<regex>` (repeatable) |
| `--skip-packages` | Skip descending into packages such as `.app` bundles |
| `--include-executables` | Also consider Mach-O binaries, `.dylib` libraries, and static archives |
| `--allow-library` | Look inside `Library` folders |
| `--allow-cloud` | Look inside iCloud Drive and other cloud-synced folders |
| `--allow-photos` | Look inside Photos libraries (requires Photos to be closed before reclaiming) |
| `-l, --list` | List every set of identical files |
| `-v, --verbose` | Log each skipped item and each replacement |
| `--delete` | `reclaim`: unlink replaced originals immediately instead of moving them to the Trash |
| `-y, --yes` | `reclaim`: skip the confirmation prompt (required when running non-interactively) |
| `-h, --help` | Show usage help |

By default, replaced originals are moved to the Trash so you can recover them if needed; disk space is freed when the Trash is emptied. Pass `--delete` to unlink originals immediately after swapping in the verified clone.

## How It Works

### 1. Scan

1. **Safe traversal:** Walks the given folders without crossing filesystem boundaries (`FTS_XDEV`) and with dataless cloud file materialization disabled (`IOPOL_MATERIALIZE_DATALESS_FILES_OFF`). System directories, protected `Library` subdirectories, Trash, volume metadata, cloud storage, `Library` folders, and `.photoslibrary` packages are skipped by default.
2. **Filtering:** Skips empty, below-threshold, dataless (evicted cloud), filesystem-compressed, sparse, and already-visited (hard-linked or overlapping) files.
3. **Source-only protection:** Files in `--source` folders, files with multiple hard links, locked or append-only files, files owned by another user, and files inside non-writable folders may act as clone sources but are never replaced.
4. **Multi-stage matching:** Groups candidates by `(volume, size)`, then by a SHA-256 digest of the first 4 KiB (skipping Mach-O binaries, `.dylib`s, and static archives unless `--include-executables` is set), and finally by a full-file SHA-256 digest plus any `com.apple.ResourceFork`. Hashing runs concurrently across all CPU cores with `F_NOCACHE`.
5. **Existing clone detection:** Checks `ATTR_CMNEXT_CLONEID`, `EF_MAY_SHARE_BLOCKS`, and physical block mappings via `fcntl(F_LOG2PHYS_EXT)` to identify files that already share storage. When choosing the clone source for a duplicate group, prefers a clone family whose blocks must stay allocated anyway (e.g., containing a source-only file), otherwise the largest existing clone family.

### 2. Reclaim (per file)

1. Reopens the target and verifies that its inode, size, `mtime`, `ctime`, link count, and flags still match the scan, and that it does not already share storage with the source.
2. Creates an APFS clone of the source next to the target using `fclonefileat()` under a temporary name and clears any inherited ACL on the temporary clone.
3. Compares the clone byte-for-byte against the target (including any resource fork) and confirms the clone shares storage with the source.
4. Reproduces the target's metadata onto the clone: extended attributes (removing any extra attributes inherited from the source), mode, owner, flags, access/modification times, creation date, and date added, then verifies the result.
5. Re-checks the target, swaps the temporary clone and target atomically via `renamex_np(..., RENAME_SWAP)` (temporarily lifting any ACL on the target so deny-delete entries do not block the swap), verifies both inodes, and transfers the ACL to the clone. If verification fails, the original is swapped back.
6. Moves the original to the Trash (with its ACL restored) or unlinks it when `--delete` is set, then restores the parent folder's modification time.

If an unrecoverable error occurs (such as a failed cleanup or unverified swap), `spacesaving` stops immediately and prints the exact paths to inspect. Sending `SIGINT` or `SIGTERM` finishes the current file cleanly before exiting.

## Development

```sh
# Run unit and APFS integration tests
swift test

# Build an optimized release binary
swift build -c release
```

## License

MIT — see [LICENSE](LICENSE).
