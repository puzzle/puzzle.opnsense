# Copyright: (c) 2023, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities used to apply OPNsense config changes"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List
import subprocess


def run_function(
    php_requirements: List[str], configure_function: str, configure_params: List = None
) -> dict:
    """
    Execute a php function optional with parameters

    :param php_requirements: A list os strings containing the location of php files which
    must be included to execute the function.
    :param configure_function: The php function to call.
    :param configure_params: An optional list of parameters to pass to the function.

    :return: Returns a dict containing stdout, stdout_lines, stderr, stderr_lines
    and rc of the command
    """
    if configure_params is None:
        configure_params = []

    # assemble the php require statements
    requirements_string = " ".join(
        ["require '" + req + "';" for req in php_requirements]
    )
    params_string = ",".join(configure_params)

    # assemble php command
    php_cmd = f"{requirements_string} {configure_function}({params_string});"
    # run command
    cmd_result = subprocess.run(
        [
            "php",
            "-r",
            php_cmd,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # do not raise exception if program fails
        # handle subprocess process error in module using stderr
        check=False,
    )

    return {
        "stdout": cmd_result.stdout.decode().strip(),
        "stdout_lines": cmd_result.stdout.decode().strip().splitlines(),
        "stderr": cmd_result.stderr.decode().strip(),
        "stderr_lines": cmd_result.stderr.decode().strip().splitlines(),
        "rc": cmd_result.returncode,
    }
