# Copyright: (c) 2023, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities used to apply OPNsense config changes"""

from __future__ import absolute_import, division, print_function

from typing import List, Optional

from ansible.module_utils.basic import AnsibleModule

__metaclass__ = type


_state: dict[str, Optional[AnsibleModule]] = {"module": None}


def initialize(module) -> None:
    """Register the AnsibleModule instance for use by run_function and run_command.

    Must be called once in each module's main() after creating the AnsibleModule
    instance. Also required in unit tests before calling any function that
    invokes _run_php_command."""
    _state["module"] = module


def _run_php_command(php_cmd: str) -> dict:
    """
    Helper method to execute a PHP command and capture the output.

    Args:
        php_cmd (str): The complete PHP command to execute.

    Returns:
        dict: A dictionary containing stdout, stderr, and return code details.
    """
    _module: Optional[AnsibleModule] = _state["module"]

    if _module is None:
        raise RuntimeError(
            "opnsense_utils._module is not set. "
            "Call opnsense_utils.initialize(module) after creating the AnsibleModule instance."
        )

    rc, stdout, stderr = _module.run_command(["php", "-r", php_cmd])
    stdout = stdout.strip()
    stderr = stderr.strip()
    return {
        "stdout": stdout,
        "stdout_lines": stdout.splitlines(),
        "stderr": stderr,
        "stderr_lines": stderr.splitlines(),
        "rc": rc,
    }


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
        params_string = ""
    else:
        params_string = ",".join(configure_params)

    # assemble the php require statements
    requirements_string = " ".join([f"require '{req}';" for req in php_requirements])

    # assemble php command
    php_cmd = f"{requirements_string} {configure_function}({params_string});"

    return _run_php_command(php_cmd)


def run_command(php_requirements: List[str], command: str) -> dict:
    """
    Executes a PHP command with specified requirements, capturing the output.

    Args:
        php_requirements (List[str]): PHP files to require before executing the command.
        command (str): The PHP command to execute.

    Returns:
        dict: A dictionary containing stdout, stderr, and return code details.
    """

    requirements_string = " ".join([f"require '{req}';" for req in php_requirements])
    php_cmd = f"{requirements_string} {command}"

    return _run_php_command(php_cmd)
