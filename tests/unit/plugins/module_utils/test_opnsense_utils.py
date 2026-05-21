# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock
from ansible_collections.puzzle.opnsense.plugins.module_utils import opnsense_utils


def test_run_function():
    mock_module = MagicMock()
    mock_module.run_command.return_value = (
        0,
        "Function executed successfully\nnext line",
        "Function failed\nnext line",
    )
    opnsense_utils.initialize(mock_module)

    expected_result = {
        "stdout": "Function executed successfully\nnext line",
        "stdout_lines": ["Function executed successfully", "next line"],
        "stderr": "Function failed\nnext line",
        "stderr_lines": ["Function failed", "next line"],
        "rc": 0,
    }

    php_requirements = ["/usr/local/etc/inc/config.inc", "/usr/local/etc/inc/util.inc"]
    configure_function = "plugins_configure"
    configure_params = ["dns", "true"]

    result = opnsense_utils.run_function(
        php_requirements, configure_function, configure_params
    )

    assert result == expected_result

    expected_command = [
        "php",
        "-r",
        "require '/usr/local/etc/inc/config.inc'; "
        "require '/usr/local/etc/inc/util.inc'; "
        "plugins_configure(dns,true);",
    ]
    mock_module.run_command.assert_called_once_with(expected_command)
