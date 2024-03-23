#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Lukas Grimm <grimm@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""services_dhcpv4 module: Module to configure dhcpv4"""

__metaclass__ = type


# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''
---
author:
  - Lukas Grimm (@ombre8)
module: services_dhcpv4
short_description: Configure DHCP server for specific Interface.
description:
  - Module to configure general system settings
options:
  interface:
    description: "The Interface the DHCP server should be configured on"
    type: str
    required: true
  enable:
    description: Wheter the Server is enabled or not
    type: bool
    default: true
    required: false
  range_from:
    description: Start of the IP Pool
    type: str
    required: false
  range_to:
    description: End of the IP Pool
    type: str
    required: false
'''

EXAMPLES = r'''
---
- name: Enable DHCP Server on LAN interface
  puzzle.opnsense.services_dhcpv4:
    interface: LAN

- name: Enable DHCP Server on guestwifi interface
  puzzle.opnsense.services_dhcpv4:
    interface: guestwifi
    enable: true
    range_from: 192.168.10.100
    range_to: 192.168.10.254
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: reconfigure_dhcpd
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: ''
        stdout_lines: []
'''
# fmt: on

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


def main():
    """
    Main function of the services_dhcpv4 module
    """

    module_args = {
        "interface": {"type": "string", "required": True},
        "enable": {"type": "bool", "default": True, "required": False},
        "range_from": {"type": "string", "required": False},
        "range_to": {"type": "string", "required": False},
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    interface = module.params.get("interface")
    enable = module.params.get("enable")
    range_from = module.params.get("range_from")
    range_to = module.params.get("range_to")

    with OPNsenseModuleConfig(
        module_name="services_dhcpv4",
        config_context_names=["services_dhcpv4"],
        check_mode=module.check_mode,
    ) as config:
        if enable != config.get("enable").text:
            config.set(value=str(enable), setting="enable")

        if range_from != config.get("range_from").text:
            config.set(value=str(range_from), setting="range_from")

        if range_to != config.get("range_to").text:
            config.set(value=str(range_to), setting="range_to")

        if config.changed:
            result["diff"] = config.diff
            result["changed"] = True

        if config.changed and not module.check_mode:
            config.save()
            result["opnsense_configure_output"] = config.apply_settings()
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
