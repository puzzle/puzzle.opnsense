#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""system_settings_general module: Module to configure general OPNsense system settings"""

# pylint: disable=duplicate-code
__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
# pylint: disable=duplicate-code
DOCUMENTATION = r'''
---
author:
  - Reto Kupferschmid (@rekup)
module: system_settings_general
short_description: Configure general settings mainly concern network-related settings like the hostname.
description:
  - Module to configure general system settings
options:
  hostname:
    description:
      - "Hostname without domain, e.g.: V(firewall)"
    type: str
    required: false
  domain:
    description:
      - The domain, e.g. V(mycorp.com), V(home), V(office), V(private), etc.
      - Do not use V(local)as a domain name. It will cause local hosts running mDNS (avahi, bonjour, etc.) to be unable to resolve local hosts not running mDNS.
    type: str
    required: false
  timezone:
    description:
      - The timezone e.g. V((Europe/Zurich), V(Etc/GMT+7), V(America/New_York), etc.
      - A list of valid timezones can be found in the OPNsense webui or in the V(/usr/share/zoneinfo/) directory on your OPNsense.
    type: str
    required: false
'''

EXAMPLES = r'''
- name: Set hostname to opnsense
  puzzle.opnsense.system_settings_general:
    hostname: "opnsense"

- name: Set domain to mycorp.com
  puzzle.opnsense.system_settings_general:
    domain: mycorp.com

- name: Set timezone to Europe/Zurich
  puzzle.opnsense.system_settings_general:
    timezone: Europe/Zurich
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: system_timezone_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: 'Setting timezone: Europe/Zurich'
        stdout_lines:
          - 'Setting timezone: Europe/Zurich'
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
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


def is_hostname(hostname: str) -> bool:
    """
    Validates hostnames

    :param hostname: A string containing the hostname

    :return: True if the provided hostname is valid, False if it's invalid
    """

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/util.inc#L704
    hostname_regex = (
        r"^(?:(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]"
        r"*[a-z0-9_])\.)*(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])$"
    )
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
    Main function of the system_settings_general module
    """

    module_args = {
        "domain": {"type": "str", "required": False},
        "hostname": {"type": "str", "required": False},
        "timezone": {"type": "str", "required": False},
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[
            ["domain", "hostname", "timezone"],
        ],
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    hostname_param = module.params.get("hostname")
    domain_param = module.params.get("domain")
    timezone_param = module.params.get("timezone")

    with OPNsenseModuleConfig(
        module_name="system_settings_general",
        config_context_names=["system_settings_general"],
        check_mode=module.check_mode,
    ) as config:
        if hostname_param:
            if not is_hostname(hostname_param):
                module.fail_json(msg="Invalid hostname parameter specified")

            if hostname_param != config.get("hostname").text:
                config.set(value=hostname_param, setting="hostname")

        if domain_param:
            if not is_domain(domain_param):
                module.fail_json(msg="Invalid domain parameter specified")

            if domain_param != config.get("domain").text:
                config.set(value=domain_param, setting="domain")

        if timezone_param:
            if not is_timezone(timezone_param):
                module.fail_json(msg="Invalid timezone parameter specified")

            if timezone_param != config.get("timezone").text:
                config.set(value=timezone_param, setting="timezone")

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
