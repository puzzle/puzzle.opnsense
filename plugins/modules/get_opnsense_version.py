#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""version module: Show current version of OPNsense Instance"""

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
DOCUMENTATION = r'''
---
author:
- Kilian Soltermann (@KiLLuuuhh)
module: get_opnsense_version
short_description: Get OPNsense version using the "opnsense-version" command.
description:
- This module runs the "opnsense-version" command on a target device and retrieves the OPNsense version.
options: {}
'''

EXAMPLES = r'''
- name: Get OPNsense Version
  opnsense_version:
  register: opnsense_version_result

- name: Display OPNsense Version
  ansible.builtin.debug:
    var: opnsense_version_result.stdout
'''

RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils import get_opnsense_version
__metaclass__ = type

def main():
    """
    returns OPNsense version of a specific Instance
    """
    module = AnsibleModule(
        argument_spec=dict(),
    )

    opnsense_version = get_opnsense_version()

    if opnsense_version:
        module.exit_json(changed=False, opnsense_version=opnsense_version)
    else:
        module.fail_json(msg="Failed to get OPNsense version")


if __name__ == '__main__':
    main()
