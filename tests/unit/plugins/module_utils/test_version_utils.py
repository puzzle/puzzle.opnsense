# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the plugins.module_utils.version_utils module."""


# This is probably intentional and required for the fixture
# pylint: disable=redefined-outer-name,unused-argument

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, MagicMock

from ansible_collections.puzzle.opnsense.plugins.module_utils import version_utils


@patch("subprocess.check_output", return_value=" OPNsense 23.1 ")
def test_version_utils(mock_object: MagicMock):
    """
    Test the retrieval of the OPNsense version using the version_utils module.

    This unit test mocks the `subprocess.check_output` method to simulate the system's response
    for the OPNsense version check. It ensures that the `get_opnsense_version` function
    correctly processes the output from the subprocess call, trimming any extraneous whitespace,
    and returns the exact version string.

    The mock is configured to return a string with leading and trailing spaces around the version
    number, which mimics the real subprocess output behavior. The test checks that the function
    under test extracts the version number accurately, without any surrounding whitespace.

    Mocks:
    - mock_subprocess_check_output (MagicMock): A mock for `subprocess.check_output` to avoid
      executing the actual command line call during testing.

    Assertions:
    - Asserts that the `get_opnsense_version` function returns "OPNsense 23.1" exactly, ensuring
      that any preprocessing of the output is handled correctly.

    Raises:
    - AssertionError: If the `get_opnsense_version` does not return the expected version string.
    """

    assert version_utils.get_opnsense_version() == "OPNsense 23.1"
