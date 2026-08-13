# Copyright (C) 2026 Jose Castillo <jcastillo@redhat.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import fnmatch


def _path_matches(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def extract_files_metadata(manifest_data, profiles=None,
                           include=None, exclude=None):
    """Walk manifest JSON and return dict keyed by source_path.

    Walks components.report.plugins.<plugin>.files[*].files_metadata[*]
    and returns {source_path: metadata_dict}.

    :param profiles: If given, only include files from plugins whose
                     profiles list intersects with this set.
    :param include:  If given, only include files whose source_path
                     matches at least one glob pattern.
    :param exclude:  If given, skip files whose source_path matches
                     any glob pattern.
    """
    result = {}
    plugins = (manifest_data.get('components', {})
               .get('report', {}).get('plugins', {}))
    filter_profiles = set(profiles) if profiles else None
    for plugin in plugins.values():
        if filter_profiles:
            plugin_profiles = set(plugin.get('profiles', []))
            if not plugin_profiles & filter_profiles:
                continue
        for file_entry in plugin.get('files', []):
            for meta in file_entry.get('files_metadata', []):
                source_path = meta.get('source_path')
                if not source_path:
                    continue
                if include and not _path_matches(source_path, include):
                    continue
                if exclude and _path_matches(source_path, exclude):
                    continue
                result[source_path] = meta
    return result


COMPARE_FIELDS = ('file_type', 'link_target', 'mode', 'uid',
                  'gid', 'owner', 'group', 'size', 'mtime_ns',
                  'sha256', 'selinux_context')

ABSENT = '—'


def _hline(widths, left, mid, right):
    return left + mid.join('─' * w for w in widths) + right


def _data_row(cells, widths):
    parts = []
    for cell, w in zip(cells, widths):
        parts.append(f' {cell:<{w - 1}}')
    return '│' + '│'.join(parts) + '│'


def _span_row(text, widths):
    inner = sum(widths) + len(widths) - 1
    s = str(text)
    max_len = inner - 2
    if len(s) > max_len:
        s = s[:max_len - 2] + '..'
    return '│' + f' {s:<{inner - 1}}' + '│'


def format_table(headers, rows, max_col=0):
    """Format rows as a box-drawn table with auto-sized columns."""
    n = len(headers)
    widths = [len(h) + 2 for h in headers]
    for row in rows:
        for i in range(min(n, len(row))):
            widths[i] = max(widths[i], len(str(row[i])) + 2)
    if max_col:
        widths = [min(w, max_col) for w in widths]

    def _trunc(text, w):
        s = str(text)
        if len(s) > w - 2:
            return s[:w - 4] + '..'
        return s

    lines = []
    lines.append(_hline(widths, '┌', '┬', '┐'))
    lines.append(_data_row(
        [_trunc(h, w) for h, w in zip(headers, widths)], widths))
    lines.append(_hline(widths, '├', '┼', '┤'))
    for row in rows:
        cells = [_trunc(row[i] if i < len(row) else '', widths[i])
                 for i in range(n)]
        lines.append(_data_row(cells, widths))
    lines.append(_hline(widths, '└', '┴', '┘'))
    return '\n'.join(lines)


def compare_snapshots(*snapshot_data, labels=None, profiles=None,
                      include=None, exclude=None):
    """Compare N snapshot manifests side by side.

    Returns only files and fields that differ across at least
    one snapshot.  Files present in all snapshots with identical
    metadata are counted but omitted from the detail.

    :param snapshot_data: Two or more manifest dicts
    :param labels:        Optional display labels (dates, names)
    :param profiles:      Optional list of profile names to filter by
    :param include:       Optional glob patterns — only matching paths
    :param exclude:       Optional glob patterns — skip matching paths
    :returns: Comparison result dict with labels, files, summary
    :raises ValueError: If fewer than 2 snapshots provided
    """
    if len(snapshot_data) < 2:
        raise ValueError("Need at least 2 snapshots to compare")

    n = len(snapshot_data)
    if labels is None:
        labels = [f"snap{i+1}" for i in range(n)]

    all_files = [extract_files_metadata(s, profiles=profiles,
                                        include=include, exclude=exclude)
                 for s in snapshot_data]

    all_paths = {}
    for idx, files in enumerate(all_files):
        for path in files:
            if path not in all_paths:
                all_paths[path] = set()
            all_paths[path].add(idx)

    changed = []
    unchanged_count = 0

    for path in sorted(all_paths):
        present = [path in files for files in all_files]

        if not all(present):
            fields = {'_status': [
                'present' if p else ABSENT for p in present
            ]}
            for field in COMPARE_FIELDS:
                vals = [all_files[i].get(path, {}).get(field)
                        for i in range(n)]
                if any(v is not None for v in vals):
                    fields[field] = [
                        v if v is not None else ABSENT
                        for v in vals
                    ]
            changed.append({'path': path, 'fields': fields})
            continue

        diff_fields = {}
        for field in COMPARE_FIELDS:
            vals = [all_files[i][path].get(field)
                    for i in range(n)]
            if any(v != vals[0] for v in vals[1:]):
                diff_fields[field] = [
                    v if v is not None else ABSENT
                    for v in vals
                ]

        if diff_fields:
            changed.append({'path': path, 'fields': diff_fields})
        else:
            unchanged_count += 1

    return {
        'labels': labels,
        'files': changed,
        'summary': {
            'total_files': len(all_paths),
            'changed_files': len(changed),
            'unchanged_files': unchanged_count,
        }
    }


def _shorten_label(label, max_len):
    """Shorten a baseline label to fit a column width.

    Strips the 'baseline-' prefix first, then the hostname
    segment if still too long, keeping the name and timestamp
    which are the distinguishing parts.
    """
    s = str(label)
    if len(s) <= max_len:
        return s
    if s.startswith('baseline-'):
        s = s[len('baseline-'):]
    if len(s) <= max_len:
        return s
    # baseline filenames are HOSTNAME-NAME-TIMESTAMP or
    # HOSTNAME-TIMESTAMP — drop hostname to keep the tail
    parts = s.split('-')
    # find where the date starts (YYYY-MM-DD pattern)
    for i, p in enumerate(parts):
        if len(p) == 4 and p.isdigit() and i > 0:
            tail = '-'.join(parts[i:])
            # include the part just before the date (the name)
            if i >= 2:
                tail = parts[i - 1] + '-' + tail
            if len(tail) <= max_len:
                return tail
            break
    return s[:max_len - 2] + '..'


def format_diff_text(diff_result):
    """Format N-snapshot comparison as a box-drawn terminal table."""
    labels = diff_result['labels']
    files = diff_result['files']
    summary = diff_result['summary']

    field_w = 22
    col_w = 30
    widths = [field_w] + [col_w] * len(labels)
    short_labels = [_shorten_label(lb, col_w - 2) for lb in labels]

    top = _hline(widths, '┌', '┬', '┐')
    mid = _hline(widths, '├', '┼', '┤')
    bottom = _hline(widths, '└', '┴', '┘')

    lines = []
    lines.append('')
    lines.append(top)
    lines.append(_data_row(['Field'] + short_labels, widths))
    lines.append(mid)

    if not files:
        lines.append(_span_row('(no differences)', widths))
    else:
        for i, entry in enumerate(files):
            if i > 0:
                lines.append(mid)
            lines.append(_span_row(entry['path'], widths))
            for field, vals in entry['fields'].items():
                cells = [f'  {field}']
                for v in vals:
                    cell = str(v) if v is not None else ABSENT
                    if len(cell) > col_w - 2:
                        cell = cell[:col_w - 4] + '..'
                    cells.append(cell)
                lines.append(_data_row(cells, widths))

    lines.append(bottom)
    lines.append(
        f' {summary["changed_files"]} changed, '
        f'{summary["unchanged_files"]} unchanged, '
        f'{summary["total_files"]} total'
    )
    lines.append('')

    return '\n'.join(lines)
