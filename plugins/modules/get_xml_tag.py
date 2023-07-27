#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Philipp Matti <matti@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Example module: Show minimal functionality of OPNsenseConfig class"""

DOCUMENTATION = r'''
---
author:
- Philipp Matti (@acteru)
module: get_xml_tag
short_description: Get specific xml tag from /confg/config.xml
description:
- Example module to use OPNsenseConfig module_utils
options:
  tag:
    description:
    - String to search for tag in xml.
    type: str
    required: true
'''

EXAMPLES = r'''
- name: Print the opnsense xml
  puzzle.opnsense.get_xml_tag:
    path: /conf/config.xml
    tag: "sysctl"
  register: xmlconfig

- name: Print return value
  ansible.builtin.debug:
    msg: "{{ xmlconfig }}"
'''

RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils import config_utils

__metaclass__ = type


def main():
    """
    Return requested key from config.xml
    """

    module_args = {
        "tag": {"type": "str", "required": True},
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = {
        'changed': False,
        'original_message': module.params,
        'message': '',
    }

    # check-mode handler
    if module.check_mode:
        module.exit_json(**result)

    config_mgr = config_utils.OPNsenseConfig()

    # Get xml via key
    result['message'] = config_mgr[str(module.params["tag"])]

    # Return results
    module.exit_json(**result)


if __name__ == '__main__':
    main()
