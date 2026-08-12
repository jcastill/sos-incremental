# Copyright (C) 2026 Jose Castillo <jcastillo@redhat.com>
#
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import glob
import json
import logging
import os
import re
from datetime import datetime, timezone

_default_log = logging.getLogger('sos')


def find_latest_snapshot(baseline_dir='/etc/sos/.baselines', name=''):
    """Find the most recent snapshot file.

    When ``name`` is empty, returns the newest snapshot regardless of
    whether it is named or unnamed.  The hostname embedded in each
    filename is intentionally ignored so that the latest snapshot on
    this host is always selected.

    When ``name`` is given, only snapshots whose filename contains
    that name segment are considered.

    :param baseline_dir: Directory to scan for snapshots
    :type baseline_dir: str

    :param name: Optional baseline name to filter snapshots
    :type name: str

    :returns: Path to the newest snapshot or None if none found
    :rtype: str or None
    """
    if name:
        pattern = os.path.join(baseline_dir,
                               f'baseline-*-{name}-*.json')
    else:
        pattern = os.path.join(baseline_dir, 'baseline-*.json')
    files = sorted(
        glob.glob(pattern),
        key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def load_snapshot(path, soslog=None):
    """Load and parse a snapshot JSON file.

    :param path: Path to the snapshot JSON file
    :type path: str

    :param soslog: Optional logger for error messages
    :type soslog: logging.Logger or None

    :returns: Parsed snapshot data dict or None on error
    :rtype: dict or None
    """
    log = soslog or _default_log
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.error(f"Failed to load snapshot '{path}' : {e}")
        return None


def save_snapshot(manifest_json, name='', hostname='',
                  baseline_dir='/etc/sos/.baselines', soslog=None):
    """Save manifest JSON as a dated snapshot.

    Writes to: ``baseline-HOSTNAME[-NAME]-YYYY-MM-DD_HH-MM-SSZ.json``
    Permissions: ``0o444`` (read-only) after write.
    Directory: created with ``0o700`` if missing.

    :param manifest_json: Manifest JSON string to write
    :type manifest_json: str

    :param name: Optional baseline name (alphanumerics, dots, hypens,
        underscores only)
    :type name: str

    :param hostname: Hostname to embed in the snapshot filename
    :type hostname: str

    :param baseline_dir: Directory to write snapshot to
    :type baseline_dir: str

    :param soslog: Optional logger for info/error messages
    :type soslog: logging.Logger or None

    :returns: Path to the saved snapshot or None on failure
    :rtype: str or None
    """
    log = soslog or _default_log

    if name and not re.match(r'^[a-zA-Z0-9._-]+$', name):
        log.error(f"Invalid baseline '{name}': "
                  "only alphanumerics, dots, hypens, "
                  "and underscores are allowed")
        return None

    date_str = datetime.now(timezone.utc).strftime(
        '%Y-%m-%d_%H-%M-%SZ')
    host_part = f"-{hostname}" if hostname else ''
    name_part = f"-{name}" if name else ''
    filename = f"baseline{host_part}{name_part}-{date_str}.json"
    baseline_path = os.path.join(baseline_dir, filename)

    try:
        os.makedirs(baseline_dir, mode=0o700, exist_ok=True)

        fd = os.open(baseline_path,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            fp = os.fdopen(fd, 'w', encoding='utf-8')
        except Exception:
            os.close(fd)
            raise
        with fp:
            fp.write(manifest_json)

        os.chmod(baseline_path, 0o444)

        log.info(f"Snapshot saved to {baseline_path}")

        return baseline_path
    except PermissionError as e:
        log.error("Permission denied writing snapshot to "
                  f"{baseline_path}: {e}")
    except OSError as e:
        log.error(
            f"Failed to save snapshot to {baseline_path}: {e}"
        )
    except Exception as e:
        log.error(f"Unexpected error saving snapshot: {e}")
    return None
