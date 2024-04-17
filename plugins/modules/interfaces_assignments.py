#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""interfaces_assignments module: Module to configure OPNsense interface settings"""

# pylint: disable=duplicate-code
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
    required: False
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
      - function: filter_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: ''
        stdout_lines: []

      - function: rrd_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: Generating RRD graphs...done.
        stdout_lines:
          - Generating RRD graphs...done.
'''
# fmt: on

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_assignments_utils import (
    InterfacesSet,
    InterfaceAssignment,
    OPNSenseInterfaceNotFoundError,
    OPNSenseDeviceNotFoundError,
    OPNSenseDeviceAlreadyAssignedError,
    OPNSenseGetInterfacesError,
)


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

    try:
        interface_assignment = InterfaceAssignment.from_ansible_module_params(
            module.params
        )

        with InterfacesSet() as interfaces_set:

            interfaces_set.update(interface_assignment)

            if interfaces_set.changed:
                result["diff"] = interfaces_set.diff
                result["changed"] = True

            if interfaces_set.changed and not module.check_mode:
                interfaces_set.save()
                result["opnsense_configure_output"] = interfaces_set.apply_settings()

                for cmd_result in result["opnsense_configure_output"]:
                    if cmd_result["rc"] != 0:
                        module.fail_json(
                            msg="Apply of the OPNsense settings failed",
                            details=cmd_result,
                        )

        # Return results
        module.exit_json(**result)

    except (
        OPNSenseInterfaceNotFoundError
    ) as opnsense_interface_not_found_error_error_message:
        module.fail_json(msg=str(opnsense_interface_not_found_error_error_message))

    except OPNSenseDeviceNotFoundError as opnsense_device_not_found_error_error_message:
        module.fail_json(msg=str(opnsense_device_not_found_error_error_message))

    except (
        OPNSenseDeviceAlreadyAssignedError
    ) as opnsense_device_already_assigned_error_message:
        module.fail_json(msg=str(opnsense_device_already_assigned_error_message))

    except OPNSenseGetInterfacesError as opnsense_get_interfaces_error_message:
        module.fail_json(msg=str(opnsense_get_interfaces_error_message))


if __name__ == "__main__":
    main()
