#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""system_access_users module: Read, write, edit operations for OPNsense Users """

# pylint: disable=duplicate-code
__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off

DOCUMENTATION = r'''
---
module: system_access_users
short_description: Manage OPNsense users
description:
    - This module allows you to manage users on an OPNsense firewall.
author:
    - Kilian Soltermann (@killuuuhh)
version_added: "1.0.0"
options:
    username:
        description:
            - The username of the OPNsense user.
        required: true
        type: str
    password:
        description:
            - The password of the OPNsense user.
        required: true
        type: str
    disabled:
        description:
            - Indicates whether the user account should be disabled.
        required: false
        default: false
        type: bool
    full_name:
        description:
            - The full name of the OPNsense user.
        required: false
        type: str
    email:
        description:
            - The email address of the OPNsense user.
        required: false
        type: str
    comment:
        description:
            - Additional comments or notes for the OPNsense user.
        required: false
        type: str
    landing_page:
        description:
            - The landing page for the OPNsense user.
        required: false
        type: str
    shell:
        description:
            - The shell for the OPNsense user.
        required: false
        type: str
    expires:
        description:
            - The expiration date for the OPNsense user account.
        required: false
        type: str
    groups:
        description:
            - A list of groups the OPNsense user belongs to.
        required: false
        type: list
        elements: str
    apikeys:
        description:
            - A list of apikeys for an OPNsense User. Generates new apikey if "" is provided.
        required: false
        type: list
        elements: str
    otp_seed:
        description:
            - The otp_seed of a OPNsense user.
        required: false
        type: str
    authorizedkeys:
        description:
            - The authorizedkeys of a OPNsense user.
        required: false
        type: str
    scope:
        description:
            - The scope of the OPNsense user.
        required: false
        type: str
    uid:
        description:
            - The UID of the OPNsense user.
        required: false
        type: str
    state:
        description:
            - The desired state of the OPNsense user.
        required: false
        choices:
            - present
            - absent
        default: present
        type: str
'''

EXAMPLES = r'''
- name: Add OPNsense user
  puzzle.opnsense.system_access_users:
    username: johndoe
    password: secret
    full_name: John Doe
    email: johndoe@example.com
    groups:
      - admins
    state: present
  register: result

- name: Remove OPNsense user
  puzzle.opnsense.system_access_users:
    username: johndoe
    state: absent
  register: result
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: "opnsense_configure_output"
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

from ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils import (
    User,
    UserSet,
    OPNSenseGroupNotFoundError,
    OPNSenseNotValidBase64APIKeyError,
)


ANSIBLE_MANAGED: str = "[ ANSIBLE ]"


def main():
    """
    Main function of the system_access_users module
    """
    module_args = {
        "username": {
            "type": "str",
            "required": True,
        },
        "password": {"type": "str", "required": True, "no_log": True},
        "disabled": {"type": "bool", "default": False},
        "full_name": {"type": "str", "required": False},
        "email": {"type": "str", "required": False},
        "comment": {"type": "str", "required": False},
        "landing_page": {"type": "str", "required": False},
        "shell": {"type": "str", "required": False},
        "expires": {"type": "str", "required": False},
        "otp_seed": {"type": "str", "required": False},
        "authorizedkeys": {"type": "str", "required": False, "no_log": True},
        "groups": {"type": "list", "required": False, "elements": "str"},
        "apikeys": {
            "type": "list",
            "required": False,
            "elements": "str",
            "no_log": False,
        },
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

    # since description matches the full_name in GUI
    module.params["full_name"] = description

    try:
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

                if ansible_user.apikeys:
                    result["generated_apikeys"] = []
                    for new_generated_api_key in ansible_user.apikeys:
                        result["generated_apikeys"].append(new_generated_api_key["key"])

                for cmd_result in result["opnsense_configure_output"]:
                    if cmd_result["rc"] != 0:
                        module.fail_json(
                            msg="Apply of the OPNsense settings failed",
                            details=cmd_result,
                        )
        module.exit_json(**result)

    except OPNSenseGroupNotFoundError as opnsense_group_not_found_error_error_message:
        module.fail_json(msg=str(opnsense_group_not_found_error_error_message))
    except (
        OPNSenseNotValidBase64APIKeyError
    ) as opnsense_not_valid_base64_apikey_error_message:
        module.fail_json(msg=str(opnsense_not_valid_base64_apikey_error_message))


if __name__ == "__main__":
    main()
