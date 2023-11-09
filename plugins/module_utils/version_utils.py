# Copyright: (c) 2023, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for versioning"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import subprocess


def get_opnsense_version() -> str:
    """
    Returns output of command opensense-version
    """
    try:
        return subprocess.check_output(args=["opnsense-version"], encoding="utf-8").strip()

    except subprocess.CalledProcessError as exc:
        return str(exc)
