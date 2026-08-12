# SoS Baseline Snapshots, Incremental Reports, and Compare

This work adds three related capabilities to sos:

1. **Baseline snapshots** -- capture file metadata (permissions, ownership, SELinux context, SHA-256 hashes) during `sos report` and save it as a dated JSON snapshot.
2. **Incremental reports** -- skip files unchanged since the last snapshot, producing smaller and faster archives.
3. **`sos compare`** -- a new subcommand that diffs two or more snapshots side by side, reporting added, removed, and changed files.

## New flags for `sos report`

| Flag | Description |
|------|-------------|
| `--baseline` | Collect enhanced file metadata and save a snapshot to `/etc/sos/.baselines/` |
| `--baseline-name NAME` | Scope snapshots by name (e.g. `production`, `staging`) |
| `--incremental` | Skip files unchanged since the last snapshot (requires `--baseline`) |

## New subcommand: `sos compare`

| Command | Description |
|---------|-------------|
| `sos compare list` | List saved snapshots with system info (hostname, kernel, arch, collection type) |
| `sos compare list --name NAME` | List only snapshots matching a name |
| `sos compare diff <id1> <id2> [...]` | N-way snapshot comparison (text or JSON output) |
| `sos compare diff --profile PROFILE` | Filter by plugin profile membership (e.g. `kernel`, `network`) |
| `sos compare diff -i PATTERN` | Include only paths matching a glob |
| `sos compare diff -e PATTERN` | Exclude paths matching a glob |
| `sos compare diff --output-format json` | Machine-readable JSON output |

## Tracked metadata

Each file in a snapshot records:

- File type, permissions (mode), UID/GID, owner/group names
- Size, modification time (`mtime_ns`), status change time (`ctime_ns`)
- SELinux security context (on SELinux-enabled systems)
- SHA-256 content hash for regular files under `/etc/`, `/boot/`, `/usr/bin/`, `/usr/sbin/`, `/lib/systemd/` (up to 10 MB)
- Symlink targets
- Collection mode (`full`, `tailed`, `skipped_unchanged`)

## Architecture

```
sos/
  __init__.py                          # Registers 'compare' component
  compare/
    __init__.py                        # SoSCompare: CLI for list/diff actions
  report/
    __init__.py                        # --baseline/--incremental flag handling
    plugins/__init__.py                # Per-file metadata collection in Plugin
    snapshot/
      store.py                         # save_snapshot(), load_snapshot(), find_latest_snapshot()
      comparison.py                    # compare_snapshots(), format_diff_text()
      incremental/
        engine.py                      # IncrementalEngine: change detection entry point
        metadata.py                    # collect_file_metadata(), file_changed(), get_file_hash()
```

Snapshots are saved as `baseline[-HOSTNAME][-NAME]-YYYY-MM-DD_HH-MM-SSZ.json` with read-only permissions (0444) under `/etc/sos/.baselines/` (created with mode 0700).

Incremental snapshots reference their parent, forming a traceable chain. Each plugin's profile membership is recorded in the manifest to support semantic filtering during comparison without importing plugin classes.

## How to test

### Prerequisites

- Python 3.8+
- Root access (sos report requires root to collect system data)
- A clone of this repository

### Manual testing

#### 1. Create a full baseline

```bash
sudo ./bin/sos report --baseline --batch
```

Verify the snapshot was created:

```bash
sudo ls -la /etc/sos/.baselines/
```

#### 2. Create a named baseline

```bash
sudo ./bin/sos report --baseline --baseline-name production --batch
```

#### 3. Run an incremental report

```bash
sudo ./bin/sos report --baseline --incremental --batch
```

The archive should be smaller because unchanged files are skipped. Check the sos log for "skipped_unchanged" entries.

#### 4. List snapshots

```bash
sudo sos compare list
sudo sos compare list --name production
```

#### 5. Diff two snapshots

```bash
# Use the date portions from the snapshot filenames
sudo sos compare diff 2026-08-01_10-00-00 2026-08-02_10-00-00

# JSON output
sudo sos compare diff 2026-08-01_10-00-00 2026-08-02_10-00-00 --output-format json

# Filter by profile
sudo sos compare diff snap1 snap2 --profile kernel

# Filter by path
sudo sos compare diff snap1 snap2 -i '/etc/*' -e '/etc/alternatives/*'
```
