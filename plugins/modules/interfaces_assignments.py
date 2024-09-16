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
version_added: "1.1.0"
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
  enabled:
    description:
      - Enable or disable the interface
    type: bool
    required: false
  locked:
    description:
      - Prevent interface removal
    type: bool
    required: false
  block_private:
    description:
        - When set, this option blocks traffic from IP addresses that are reserved for private networks as per RFC 1918 (10/8, 172.16/12, 192.168/16) as well as loopback addresses (127/8) and Carrier-grade NAT addresses (100.64/10). This option should only be set for WAN interfaces that use the public IP address space.
      type: bool
      required: false
  block_bogons:
    description:
        - When set, this option blocks traffic from IP addresses that are reserved for private networks as per RFC 1918 (10/8, 172.16/12, 192.168/16) as well as loopback addresses (127/8) and Carrier-grade NAT addresses (100.64/10). This option should only be set for WAN interfaces that use the public IP address space.
      type: bool
      required: false
  ipv4_configuration_type:
    description:
      - 
    type: str
    required: false
  ipv6_configuration_type:
    description:
      - 
    type: str
    required: false
  ipv4_address:
    description:
      - 
    type: str
    required: false
  # ipv4_subnet:
  #   description:
  #     - 
  #   type: int
  #   required: false
  ipv4_gateway:
    description:
      - 
    type: str
    required: false
  ipv6_address:
    description:
      - 
    type: str
    required: false
  # ipv6_subnet:
  #   description:
  #     - 
  #   type: int
  #   required: false
  ipv6_gateway:
    description:
      - 
    type: str
    required: false
  track6_interface:
    description:
      - 
    type: str
    required: false
  track6_prefix_id:
    description:
      - 
    type: int
    required: false
  mac_address:
    description:
      - 
    type: str
    required: false
  promiscuous_mode:
    description:
      - 
    type: bool
    required: false
  mtu:
    description:
      - If you leave this field blank, the adapter's default MTU will be used. This is typically 1500 bytes but can vary in some circumstances.
    type: int
    required: false
  mss:
    description:
      - If you enter a value in this field, then MSS clamping for TCP connections to the value entered above minus 40 (IPv4) or 60 (IPv6) will be in effect (TCP/IP header size).
    type: int
    required: false
  dynamic_gateway:
    description:
      - If the destination is directly reachable via an interface requiring no intermediary system to act as a gateway, you can select this option which allows dynamic gateways to be created without direct target addresses. Some tunnel types support this.
    type: bool
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
    description: A list of the executed OPNsense configure function along with their respective stdout, stderr and rc
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
        "enabled": {"type": "bool", "required": False, "default": False},
        "locked": {"type": "bool", "required": False, "default": False},
        "block_private": {"type": "bool", "required": False, "default": False},
        "block_bogons": {"type": "bool", "required": False, "default": False},
        "ipv4_address": {"type": "str", "required": False},
        "ipv4_subnet": {"type": "int", "required": False},
        "ipv4_gateway": {"type": "str", "required": False},
        "ipv6_address": {"type": "str", "required": False},
        "ipv6_subnet": {"type": "int", "required": False},
        "ipv6_gateway": {"type": "str", "required": False},
        "track6_interface": {"type": "str", "required": False},
        "track6_prefix_id": {"type": "int", "required": False},
        "mac_address": {"type": "str", "required": False},
        "promiscuous_mode": {"type": "bool", "required": False, "default": False},
        "mtu": {"type": "int", "required": False},
        "mss": {"type": "int", "required": False},
        "dynamic_gateway": {"type": "bool", "required": False, "default": False},
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

    interface_assignment = InterfaceAssignment.from_ansible_module_params(module.params)

    with InterfacesSet() as interfaces_set:

        try:
            interfaces_set.update(interface_assignment)

        except (
            OPNSenseDeviceNotFoundError
        ) as opnsense_device_not_found_error_error_message:
            module.fail_json(msg=str(opnsense_device_not_found_error_error_message))

        except (
            OPNSenseDeviceAlreadyAssignedError
        ) as opnsense_device_already_assigned_error_message:
            module.fail_json(msg=str(opnsense_device_already_assigned_error_message))

        except OPNSenseGetInterfacesError as opnsense_get_interfaces_error_message:
            module.fail_json(msg=str(opnsense_get_interfaces_error_message))

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


if __name__ == "__main__":
    main()
