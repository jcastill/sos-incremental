# Copyright (C) 2026 Jose Castillo <jcastillo@redhat.com>.
#
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import hashlib
import logging
import os
import stat

try:
    import grp
    import pwd
except ImportError:
    grp = None
    pwd = None

try:
    import selinux
    selinux_enabled = selinux.is_selinux_enabled()
except ImportError:
    selinux = None
    selinux_enabled = False

_default_log = logging.getLogger('sos')

HASH_CRITICAL_PATHS = (
    '/etc/',
    '/boot/',
    '/usr/bin/',
    '/usr/sbin/',
    '/lib/systemd/'
)
HASH_SIZE_LIMIT = 10 * 1024 * 1024

SKIP_FS_TYPES = {
    'proc', 'sysfs', 'tmpfs', 'devtmpfs', 'devpts', 'debugfs',
    'tracefs', 'cgroup', 'cgroup2', 'pstore', 'bpf', 'configfs',
    'securityfs', 'fusectl', 'hugetlbfs', 'mqueue', 'ramfs',
    'nfs', 'nfs4', 'cifs', 'smbfs', 'autofs', 'fuse.sshfs',
    'ncpfs', 'afs', 'glusterfs', 'lustre'
}

_FILE_TYPE_MAP = {
    stat.S_ISREG: "file",
    stat.S_ISDIR: "directory",
    stat.S_ISBLK: "block_device",
    stat.S_ISCHR: "char_device",
    stat.S_ISFIFO: "fifo",
    stat.S_ISLNK: "symlink",
    stat.S_ISSOCK: "socket",
}

_mounts_cache = None


def _get_mounts():
    """Parse /proc/mounts and return a sorted list of
    (mount_point, fs_type).

    Results are cached after the first call. Use
    ``_invalidate_mounts_cache()`` to force a re-read (e.g. in
    tests or after a long-running collection).
    """
    global _mounts_cache
    if _mounts_cache is not None:
        return _mounts_cache
    try:
        with open('/proc/mounts', 'r', encoding='UTF-8') as f:
            mounts = []
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mounts.append((parts[1], parts[2]))
            mounts.sort(key=lambda x: len(x[0]), reverse=True)
            _mounts_cache = mounts
    except OSError:
        _mounts_cache = []
    return _mounts_cache


def _invalidate_mounts_cache():
    """Reset the cached mount table so the next call re-reads
    /proc/mounts."""
    global _mounts_cache
    _mounts_cache = None


def _get_filesystem_type(path):
    """Get the filesystem type for a given path by parsing
    /proc/mounts.

    Returns the filesystem type (e.g., 'ext4', 'nfs', 'proc',
    'sysfs') or None if the filesystem type cannot be determined.

    :param path: The filesystem path to check
    :type path: str

    :returns: Filesystem type or None
    :rtype: str or None
    """
    for mount_point, fs_type in _get_mounts():
        if (mount_point == '/'
                or path == mount_point
                or path.startswith(mount_point + '/')):
            return fs_type
    return None


def should_skip_file_metadata(path):
    """Determine if size/mtime metadata should be skipped for a
    file.

    Metadata collection is skipped for files on:
    - Pseudo filesystems (proc, sysfs, debugfs, etc)
    - Network filesystems (nfs, nfs4, cifs, etc)

    :param path: The filesystem path to check
    :type path: str

    :returns: True if metadata should be skipped
    :rtype: bool
    """
    fs_type = _get_filesystem_type(path)
    return fs_type in SKIP_FS_TYPES if fs_type else False


def get_file_hash(path, algorithm='sha256', max_size=None,
                  soslog=None):
    """Calculate the hash of a file for content comparison.

    :param path: Path to the file to hash
    :type path: str

    :param algorithm: Hash algorithm to use (default: sha256)
    :type algorithm: str

    :param max_size: Maximum file size to hash in bytes
        (default: 10MB)
    :type max_size: int or None

    :param soslog: Optional logger for debug messages
    :type soslog: logging.Logger or None

    :returns: Hexadecimal hash string or None if file is too
        large or we got an error
    :rtype: str or None
    """
    log = soslog or _default_log

    if max_size is None:
        max_size = HASH_SIZE_LIMIT

    try:
        file_size = os.path.getsize(path)
        if file_size > max_size:
            log.debug(
                f"Skipping hash for '{path}': size {file_size} "
                f"exceeds limit {max_size}"
            )
            return None

        h = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        log.debug(f"Failed to hash '{path}': {e}")
        return None


def collect_file_metadata(path, file_stat=None, soslog=None):
    """Collect comprehensive file metadata for snapshot comparison.

    Collects file metadata including size, timestamps, permissions,
    ownership, SELinux context, and (for critical files) content
    hash.

    :param path: The filesystem path to collect metadata for
    :type path: str

    :param file_stat: Optional pre-computed stat object to avoid
        re-stat
    :type file_stat: os.stat_result or None

    :param soslog: Optional logger for debug messages
    :type soslog: logging.Logger or None

    :returns: Dictionary of file metadata or None on error
    :rtype: dict or None
    """
    log = soslog or _default_log

    if file_stat is None:
        try:
            file_stat = os.lstat(path)
        except OSError as e:
            log.debug(f"Failed to stat '{path}': {e}")
            return None

    metadata = {
        "path": path.lstrip('/'),
        "source_path": path,
        "size": file_stat.st_size,
        "mtime_ns": file_stat.st_mtime_ns,
        "ctime_ns": file_stat.st_ctime_ns,
        "mode": format(stat.S_IMODE(file_stat.st_mode), '04o'),
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
    }

    try:
        if pwd:
            metadata["owner"] = pwd.getpwuid(
                file_stat.st_uid).pw_name
        if grp:
            metadata["group"] = grp.getgrgid(
                file_stat.st_gid).gr_name
    except (KeyError, OSError):
        pass

    if stat.S_ISREG(file_stat.st_mode):
        metadata["file_type"] = "file"
    elif stat.S_ISDIR(file_stat.st_mode):
        metadata["file_type"] = "directory"
    elif stat.S_ISBLK(file_stat.st_mode):
        metadata["file_type"] = "block_device"
    elif stat.S_ISCHR(file_stat.st_mode):
        metadata["file_type"] = "char_device"
    elif stat.S_ISFIFO(file_stat.st_mode):
        metadata["file_type"] = "fifo"
    elif stat.S_ISLNK(file_stat.st_mode):
        metadata["file_type"] = "symlink"
        try:
            metadata["link_target"] = os.readlink(path)
        except OSError:
            pass
    elif stat.S_ISSOCK(file_stat.st_mode):
        metadata["file_type"] = "socket"
    else:
        metadata["file_type"] = "unknown"

    if selinux_enabled:
        try:
            context = selinux.lgetfilecon(path)
            if context and len(context) > 1:
                metadata["selinux_context"] = context[1]
        except OSError:
            pass

    if stat.S_ISREG(file_stat.st_mode):
        if any(path.startswith(cpath)
               for cpath in HASH_CRITICAL_PATHS):
            file_hash = get_file_hash(path, soslog=log)
            if file_hash:
                metadata["sha256"] = file_hash

    return metadata


def file_changed(path, current_stat, prev_meta, soslog=None):
    """Check if a file has changed compared to previous snapshot.

    :param path: The filesystem path to check
    :type path: str

    :param current_stat: Current stat result for the file
    :type current_stat: os.stat_result

    :param prev_meta: Previous snapshot metadata dict for
        comparison
    :type prev_meta: dict

    :param soslog: Optional logger for debug messages
    :type soslog: logging.Logger or None

    :returns: True if the file has changed
    :rtype: bool
    """
    current_type = next(
        (t for check, t in _FILE_TYPE_MAP.items()
         if check(current_stat.st_mode)), "unknown")
    if current_type != prev_meta.get('file_type'):
        return True

    if current_stat.st_size != prev_meta.get('size'):
        return True
    if current_stat.st_mtime_ns != prev_meta.get('mtime_ns'):
        return True
    current_mode = format(
        stat.S_IMODE(current_stat.st_mode), '04o')
    if current_mode != prev_meta.get('mode'):
        return True
    if current_stat.st_uid != prev_meta.get('uid'):
        return True
    if current_stat.st_gid != prev_meta.get('gid'):
        return True
    if prev_meta.get('file_type') == 'symlink':
        try:
            current_target = os.readlink(path)
        except OSError:
            return True
        if current_target != prev_meta.get('link_target'):
            return True
    if any(path.startswith(p) for p in HASH_CRITICAL_PATHS):
        prev_hash = prev_meta.get('sha256')
        if prev_hash is not None:
            current_hash = get_file_hash(
                path, soslog=soslog or _default_log)
            if current_hash is None:
                return True
            if current_hash != prev_hash:
                return True
    return False
