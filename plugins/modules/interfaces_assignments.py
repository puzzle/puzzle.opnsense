#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""interfaces_assignments module: Module to configure OPNsense interface settings"""

__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''
---
author:
  - Kilian Soltermann (@killuuuhh)
module: interfaces_assignments
short_description: This module can be used to assign interfaces to network ports and network IDs to new interfaces.
description:
  - Module to assign interfaces to network ports and network IDs to new interfaces.
options:
  identifier:
    description:
      - "Technical identifier of the interface, used by hasync for example"
    type: str
    required: true
  device:
    description:
      - Physical Device Name eg. vtnet0, ipsec1000 etc,.
    type: str
    required: true
  description:
    description:
      - Interface name shown in the GUI. Identifier in capital letters if not provided.
      - Input will be trimmed, as no whitespaces are allowed.
    type: str
    required: false
'''

EXAMPLES = r'''
- name: Assign Vagrant interface to device em4
  puzzle.opnsense.interfaces_assignments:
    identifier: "VAGRANT"
    device: "em4"

- name: Create new assignment
  puzzle.opnsense.interfaces_assignments:
    identifier: "lan"
    device: "vtnet1"
    description: "lan_interface"
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: interfaces_assignments
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: 'Assigning interface: lan' # ToDo
        stdout_lines:
          - 'Assigning interface: lan' # ToDo
      - function: system_trust_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: Writing trust files...done.
        stdout_lines:
          - Writing trust files...done.
'''
# fmt: on

import os
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_assignments_utils import (
    InterfacesSet,
    Interface_assignment,
)


def is_interface(interface: str) -> bool:
    """
    Checks if interface exists on OPNsense

    :param interface: A string containing the interface

    :return: True if the provided interface is existing, False if it's not existing
    """

    return re.match(hostname_regex, hostname) is not None


def is_domain(domain: str) -> bool:
    """
    Validates domain

    :param hostname: A string containing the domain

    :return: True if the provided domain is valid, False if it's invalid
    """

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/util.inc#L716
    domain_regex = (
        r"^(?:(?:[a-z0-9]|[a-z0-9][a-z0-9\-]*"
        r"[a-z0-9])\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$"
    )
    return re.match(domain_regex, domain) is not None


def is_timezone(tz: str) -> bool:
    """
    Validates timezones

    :param tz: A string containing the timezone

    :return: True if the provided timezone is valid, False if it's invalid
    """
    tz_path = os.path.join("/usr/share/zoneinfo/", tz)
    return os.path.isfile(tz_path)


def main():
    """
    Main function of the interfaces_assignments module
    """

    module_args = {
        "identifier": {"type": "str", "required": True},
        "device": {"type": "str", "required": True},
        "description": {"type": "str", "required": False},
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[
            ["identifier", "device", "description"],
        ],
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    interface_assignment = Interface_assignment.from_ansible_module_params(module.params)

    with InterfacesSet() as interfaces_set:
        interfaces_set.update(interface_assignment)

        if interfaces_set.changed:
            interfaces_set.save()
        # if not is_interface(identifier_param):
        #    module.fail_json(msg="Invalid interface parameter specified")
    #
    # if hostname_param != config.get("hostname").text:
    #    config.set(value=hostname_param, setting="hostname")

    # if device_param:
    #    if not is_domain(domain_param):
    #        module.fail_json(msg="Invalid domain parameter specified")
    #
    #    if domain_param != config.get("domain").text:
    #        config.set(value=domain_param, setting="domain")
    #
    # if description_param:
    #    if not is_timezone(timezone_param):
    #        module.fail_json(msg="Invalid timezone parameter specified")
    #
    #    if timezone_param != config.get("timezone").text:
    #        config.set(value=timezone_param, setting="timezone")
    #
    # if config.changed:
    #    result["diff"] = config.diff
    #    result["changed"] = True
    #
    # if config.changed and not module.check_mode:
    #    config.save()
    #    result["opnsense_configure_output"] = config.apply_settings()
    #    for cmd_result in result["opnsense_configure_output"]:
    #        if cmd_result["rc"] != 0:
    #            module.fail_json(
    #                msg="Apply of the OPNsense settings failed",
    #                details=cmd_result,
    #            )

    # Return results
    module.exit_json(**result)


if __name__ == "__main__":
    main()
