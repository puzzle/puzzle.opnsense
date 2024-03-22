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

RETURN = ''' # TODO
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: system_syslog_start
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: 'Configuring system logging...done.'
        stdout_lines:
          - 'Configuring system logging...done.'
'''
# fmt: on

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)
