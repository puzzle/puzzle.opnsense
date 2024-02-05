#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Copyright: (c) 2023, Puzzle ITC, Fabio Bertagna <bertagna@puzzle.ch>, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""Firewall rules module: Read, write, edit operations for firewall rules """

__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off

DOCUMENTATION = r'''
---
'''

EXAMPLES = r'''

'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: "system_cron_configure"
        params: []
        rc: 0
        stderr: ""
        stderr_lines: []
        stdout: ""
        stdout_lines: []
      - function: "filter_configure"
        params: []
        rc: 0
        stderr: ""
        stderr_lines: []
        stdout: ""
        stdout_lines: []
'''
# fmt: on
from typing import Optional

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.puzzle.opnsense.plugins.module_utils.users_utils import User, UserSet


ANSIBLE_MANAGED: str = "[ ANSIBLE ]"


def main():
    module_args = {
        "username": {
            "type": "str",
            "required": True,
        },
        "password": {"type": "str", "required": True},
        "disabled": {"type": "bool", "default": False},
        "full_name": {"type": "str", "required": False},
        "email": {"type": "str", "required": False},
        "comment": {"type": "str", "required": False},
        "landing_page": {"type": "str", "required": False},
        "shell": {"type": "str", "required": False},
        "expires": {"type": "str", "required": False},
        "groups": {"type": "str", "required": False},
        "scope": {"type": "str", "required": False},
        "uid": {"type": "str", "required": False},
        "state": {
            "type": "str",
            "default": "present",
            "choices": ["present", "absent"],
        },
    }

    module: AnsibleModule = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }
    # make description ansible-managed
    description: Optional[str] = module.params["full_name"]

    if description and ANSIBLE_MANAGED not in description:
        description = f"{ANSIBLE_MANAGED} - {description}"
    else:
        description = ANSIBLE_MANAGED

    module.params["full_name"] = description

    ansible_user: User = User.from_ansible_module_params(module.params)

    ansible_user_state: str = module.params.get("state")

    with UserSet() as user_set:
        if ansible_user_state == "present":
            user_set.add_or_update(ansible_user)
        elif ansible_user_state == "absent":
            user_set.delete(ansible_user)

        if user_set.changed:
            result["diff"] = user_set.diff
            result["changed"] = True

        if user_set.changed and not module.check_mode:
            user_set.save()
            result["opnsense_configure_output"] = user_set.apply_settings()
            for cmd_result in result["opnsense_configure_output"]:
                if cmd_result["rc"] != 0:
                    module.fail_json(
                        msg="Apply of the OPNsense settings failed",
                        details=cmd_result,
                    )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
