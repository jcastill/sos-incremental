# Copyright (C) 2026 Jose Castillo <jcastillo@redhat.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.component import SoSComponent
from sos.report.snapshot.comparison import (compare_snapshots,
                                            format_diff_text,
                                            format_table)

import glob
import json
import os


class SoSCompare(SoSComponent):

    desc = "Compare baseline snapshots for system diff detection"
    load_probe = False

    arg_defaults = {
        'action': '',
        'identifiers': [],
        'name': '',
        'baseline_dir': '/etc/sos/.baselines',
        'output_format': 'text',
        'profiles': [],
        'include': [],
        'exclude': [],
    }

    @classmethod
    def add_parser_options(cls, parser):
        parser.add_argument('action', choices=['diff', 'list'],
                            help='action to perform')
        parser.add_argument('identifiers', nargs='*', default=[],
                            help="baseline dates, names, or paths "
                                 "(2 or more for diff)")
        parser.add_argument('--name', default='',
                            help='filter by baseline name')
        parser.add_argument('--output-format',
                            choices=['text', 'json'], default='text',
                            dest='output_format',
                            help='output format (default: text)')
        parser.add_argument('-p', '--profile', '--profiles',
                            action='extend', dest='profiles', type=str,
                            default=[],
                            help='only compare files from plugins '
                                 'belonging to these profiles')
        parser.add_argument('-i', '--include',
                            action='extend', dest='include', type=str,
                            default=[],
                            help='only include paths matching these '
                                 'glob patterns (e.g. "/etc/*")')
        parser.add_argument('-e', '--exclude',
                            action='extend', dest='exclude', type=str,
                            default=[],
                            help='exclude paths matching these '
                                 'glob patterns (e.g. "/proc/*")')

    def execute(self):
        if self.opts.action == 'list':
            self._do_list()
        elif self.opts.action == 'diff':
            self._do_diff()

    @staticmethod
    def _get_snapshot_info(data):
        """Extract system and snapshot info from a manifest dict"""
        snap = (data.get('components', {})
                .get('report', {}).get('snapshot', {}))
        system = snap.get('system', {})
        return {
            'hostname': system.get('hostname', ''),
            'kernel': system.get('kernel', ''),
            'arch': system.get('arch', ''),
            'collection_type': snap.get('collection_type', ''),
        }

    def _read_json(self, path):
        """Load and parse a JSON file, logging errors on failure"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            self.ui_log.error(
                f"Failed to load baseline '{path}': {e}")
            return None

    def _load_baseline(self, identifier):
        """Load a baseline JSON file by date, name, or full path"""
        baseline_dir = self.opts.baseline_dir
        real_base = os.path.realpath(baseline_dir)

        # Full path provided — only accept path-like identifiers
        if os.sep in identifier or identifier.startswith(os.sep):
            if not os.path.isfile(identifier):
                self.ui_log.error(
                    f"No baseline found at path '{identifier}'")
                self._list_available()
                return None
            real_path = os.path.realpath(identifier)
            if not real_path.startswith(real_base + os.sep):
                self.ui_log.error(
                    f"Baseline path '{identifier}' is outside "
                    f"the baseline directory '{baseline_dir}'")
                return None
            return self._read_json(real_path)
        # Direct filename match (with or without .json)
        for suffix in ('', '.json'):
            direct = os.path.join(baseline_dir, identifier + suffix)
            if os.path.isfile(direct):
                real_direct = os.path.realpath(direct)
                if not real_direct.startswith(real_base + os.sep):
                    continue
                return self._read_json(real_direct)
        # Glob match — hostname is embedded in filename so we
        # wildcard around the identifier to find it.
        matches = glob.glob(
            os.path.join(baseline_dir,
                         f"baseline-*{glob.escape(identifier)}*.json"))
        if matches:
            matches.sort(key=os.path.getmtime, reverse=True)
            return self._read_json(matches[0])
        self.ui_log.error(f"No baseline found matching '{identifier}'")
        self._list_available()
        return None

    def _list_available(self, name=''):
        """Print available baselines in a formatted table"""
        baseline_dir = self.opts.baseline_dir
        if name:
            pattern = os.path.join(baseline_dir,
                                   f'baseline-*-{name}-*.json')
        else:
            pattern = os.path.join(baseline_dir, 'baseline-*.json')
        files = sorted(
            glob.glob(pattern),
            key=os.path.getmtime, reverse=True)
        if not files:
            self.ui_log.info("No baseline snapshots found.")
            return
        headers = ['Snapshot', 'Size', 'Location', 'Type']
        rows = []
        for f in files:
            size = os.path.getsize(f)
            fname = os.path.basename(f)
            data = self._read_json(f)
            ctype = ''
            if data:
                info = self._get_snapshot_info(data)
                ctype = info['collection_type']
            rows.append([fname, f'{size:,} B', f, ctype])
        self.ui_log.info(format_table(headers, rows, max_col=52))

    def _do_list(self):
        self._list_available(name=self.opts.name)

    def _do_diff(self):
        ids = self.opts.identifiers
        if len(ids) < 2:
            self.ui_log.error(
                "diff requires at least two identifiers: "
                "sos compare diff <id1> <id2> [<id3> ...]")
            return
        if len(ids) > 3:
            self.ui_log.warning(
                f"Comparing {len(ids)} snapshots — text output "
                "may exceed terminal width. Consider using "
                "--output-format json or comparing fewer "
                "snapshots at a time (recommended: 3 or fewer).")
        snapshots = []
        labels = []
        for ident in ids:
            data = self._load_baseline(ident)
            if data is None:
                return
            snapshots.append(data)
            labels.append(ident)
        hostnames = set()
        for snap in snapshots:
            info = self._get_snapshot_info(snap)
            if info['hostname']:
                hostnames.add(info['hostname'])
        if len(hostnames) > 1:
            self.ui_log.warning(
                "WARNING: comparing snapshots from different "
                f"hosts: {', '.join(sorted(hostnames))}")
        result = compare_snapshots(*snapshots, labels=labels,
                                   profiles=self.opts.profiles or None,
                                   include=self.opts.include or None,
                                   exclude=self.opts.exclude or None)
        if self.opts.output_format == 'json':
            self.ui_log.info(
                json.dumps(result, indent=4, default=str))
        else:
            self.ui_log.info(format_diff_text(result))
