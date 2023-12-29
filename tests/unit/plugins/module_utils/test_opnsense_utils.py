# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the plugins.module_utils.opnsense_utils module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import subprocess
from unittest.mock import patch, MagicMock
from ansible_collections.puzzle.opnsense.plugins.module_utils import opnsense_utils


@patch("subprocess.run")
def test_run_function(mock_subprocess_run: MagicMock):
    """
    Test the `run_function` utility which executes a PHP function with optional parameters.

    This unit test mocks the `subprocess.run` method to simulate the execution of a PHP script
    that includes specific PHP files and calls a given function with parameters, if any.
    The purpose is to ensure that the `run_function` utility correctly constructs the PHP command,
    executes it, and returns the standard output.

    The mock is set up to ensure that `subprocess.run` behaves as if the PHP script was executed
    successfully, returning an output as expected.

    Mocks:
    - mock_subprocess_run (MagicMock): A mock for `subprocess.run` to prevent the actual execution
      of the PHP command during testing. It is configured to simulate a successful execution with
      a predetermined standard output.

    Assertions:
    - Asserts that `run_function` returns the standard output correctly processed as a string.

    Raises:
    - AssertionError: If the `run_function` does not return the expected standard output string.
    """

    # Mock the subprocess.run to return a predefined output
    mock_subprocess_run.return_value.stdout = (
        b"Function executed successfully\nnext line"
    )
    mock_subprocess_run.return_value.stderr = b"Function failed\nnext line"
    mock_subprocess_run.return_value.returncode = 0

    expected_result = {
        "stdout": "Function executed successfully\nnext line",
        "stdout_lines": ["Function executed successfully", "next line"],
        "stderr": "Function failed\nnext line",
        "stderr_lines": ["Function failed", "next line"],
        "rc": 0,
    }

    # Define the PHP requirements and the function with parameters to be tested
    php_requirements = ["/usr/local/etc/inc/config.inc", "/usr/local/etc/inc/util.inc"]
    configure_function = "plugins_configure"
    configure_params = ["dns", "true"]

    # Call run_function with the test parameters
    result = opnsense_utils.run_function(
        php_requirements, configure_function, configure_params
    )

    # Assert the result matches the mocked subprocess result
    assert result == expected_result

    # Assert the subprocess.run was called with the expected command
    expected_command = [
        "php",
        "-r",
        "require '/usr/local/etc/inc/config.inc'; "
        "require '/usr/local/etc/inc/util.inc'; "
        "plugins_configure(dns,true);",
    ]

    mock_subprocess_run.assert_called_with(
        expected_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
