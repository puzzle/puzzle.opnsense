# Copyright: (c) 2023, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for versioning"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import subprocess

class OPNSenseConfigUsageError(Exception):
    """
    Error Class to be raised in improper module usage
    """


def get_opnsense_version() -> str:
    """
    Returns output of command opensense-version
    """
    try:
        return subprocess.check_output(
            args=["opnsense-version"], encoding="utf-8"
        ).strip()

    except subprocess.CalledProcessError as exc:
        raise OPNSenseConfigUsageError(
            f"There was an error getting the version {exc}"
        ) from subprocess.CalledProcessError
