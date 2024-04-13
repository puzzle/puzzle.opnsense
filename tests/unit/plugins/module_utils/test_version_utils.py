# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils module."""


# This is probably intentional and required for the fixture
# pylint: disable=redefined-outer-name,unused-argument

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import patch, MagicMock

from ansible_collections.puzzle.opnsense.plugins.module_utils import version_utils

TEST_VERSION: str = """{
    "product_abi": "23.1",
    "product_arch": "amd64",
    "product_copyright_owner": "Deciso B.V.",
    "product_copyright_url": "https://www.deciso.com/",
    "product_copyright_years": "2014-2023",
    "product_email": "project@opnsense.org",
    "product_flavour": "OpenSSL",
    "product_hash": "b2937eb0b",
    "product_id": "opnsense",
    "product_name": "OPNsense",
    "product_nickname": "Quintessential Quail",
    "product_series": "23.1",
    "product_tier": "1",
    "product_version": "23.1",
    "product_website": "https://opnsense.org/"
    }
    """


@patch("subprocess.check_output", return_value=TEST_VERSION)
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
    - Asserts that the `get_opnsense_version` function returns "23.1" exactly, ensuring
      that any preprocessing of the output is handled correctly.

    Raises:
    - AssertionError: If the `get_opnsense_version` does not return the expected version string.
    """

    assert version_utils.get_opnsense_version() == "23.1"
