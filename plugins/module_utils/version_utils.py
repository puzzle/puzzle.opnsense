# Copyright: (c) 2023, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for versioning"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import subprocess


class OPNSenseVersionUsageError(Exception):
    """
    Error Class to be raised in improper module usage
    """


def get_opnsense_version() -> str:
    """
    Returns output of command opensense-version
    """
    try:
        version_string = subprocess.check_output(
            args=["opnsense-version", "-O"], encoding="utf-8"
        ).strip()

    except subprocess.CalledProcessError as exc:
        raise OPNSenseVersionUsageError(
            f"There was an error getting the version {exc}"
        ) from exc

    try:
        version_dict = json.loads(version_string)
    except json.decoder.JSONDecodeError as exc:
        raise OPNSenseVersionUsageError(
            f"There was an error getting the version {exc}"
        ) from exc

    product_version = version_dict.get("product_series", None)
    if product_version is None:
        raise OPNSenseVersionUsageError(
            "There was an error getting the version: "
            "product_version not found in opnsense-version -O command output"
        )
    return product_version
