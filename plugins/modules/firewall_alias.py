#!/usr/bin/python
# Copyright: (c) 2024, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""firewall_alias module: Module to configure opnsense firewall aliases"""

# pylint: disable=duplicate-code
__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off

DOCUMENTATION = r'''
---
author:
  - Kilian Soltermann (@killuuuhh)
module: firewall_alias
short_description: Configure firewall aliases.
version_added: 1.4.0
description: Module to configure opnsense firewall aliases
options:
  enabled:
    description:
      - If set to True, the Alias will be enabled
      - If set to False, the Alias will not be enabled
    type: bool
    required: false
    default: true
  name:
    description:
      - The name of the alias may only consist of the characters "a-z, A-Z, 0-9
        and _"
    type: str
    required: true
  type:
    description:
      - The type used for the Alias
      - hosts (Single hosts by IP or Fully Qualified Domain Name or host
        exclusions (starts with '!' sign))
      - networks (Entire network p.e. 192.168.1.1/24 or network exclusion eg
        !192.168.1.0/24)
      - ports (Port numbers or a port range like 20:30)
      - urls (A table of IP addresses that are fetched once)
      - urltable (A table of IP addresses that are fetched on regular
        intervals.)
      - geoip (Select countries or whole regions) disclaimer -> validation is not supported at this point
      - networkgroup (Combine different network type aliases into one)
      - macaddress (MAC address or partial mac addresses like f4:90:ea)
      - bgpasn (Maps autonomous system (AS) numbers to networks where they
        are responsible for) supported >= version 23.7
      - dynamicipv6host (A Host entry that will auto update on a
        prefixchange) supported >= version 23.7
      - opnvpngroup (Map user groups to logged in OpenVPN users) supported
        >= version 23.1
      - internal (Internal aliases which are managed by the product)
      - external (Externally managed alias, this only handles the
        placeholder. Content is set from another source (plugin, api call,
        etc))
    type: str
    choices:
      - host
      - network
      - port
      - url
      - urltable
      - geoip
      - networkgroup
      - macaddress
      - bgpasn
      - dynamicipv6host
      - opnvpngroup
      - internal
      - external
    required: true
  content:
    description:
      - Content of the alias
    type: list
    elements: str
    required: false
  protocol:
    description:
      - Protocol of BGP ASN Entry
    type: list
    elements: str
    required: false
    choices:
      - IPv4
      - IPv6
      - ''
  statistics:
    description:
      - Maintain a set of counters for each table entry
    type: bool
    required: false
    default: false
  description:
    description:
      - Description of the Alias
    type: str
    required: false
  refreshfrequency:
    description:
      - The frequency that the list will be refreshed, in days + hours,
        so 1 day and 8 hours means the alias will be refreshed after 32 hours.
    type: dict
    required: false
    suboptions:
      days:
        description:
          - Number of days for the refresh frequency.
        type: int
        required: false
      hours:
        description:
          - Number of hours for the refresh frequency.
        type: int
        required: false
  interface:
    description:
      - Select the interface for the V6 dynamic IP
    type: str
    required: false
  state:
    description: Whether alias should be added or removed.
    required: false
    type: str
    default: present
    choices: [present, absent]
'''

EXAMPLES = r'''
- name: Create an Host Alias with the content 10.0.0.1
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeHost
    type: host
    statistics: false
    description: Test Alias with type Host
    content: 10.0.0.1

- name: Create a URL Alias with the content www.puzzle.ch
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeURL
    type: url
    statistics: false
    description: Test Alias with type URL
    content: www.puzzle.ch

- name: Create a URLTable Alias with the content www.google.ch, www.puzzle.ch
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeURLTable
    type: urltable
    description: Test Alias with type URLTable
    refreshfrequency:
      days: 1
      hours: 2
    content:
      - www.google.ch
      - www.puzzle.ch

- name: Create a GeoIP Alias with the content CH, DE
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeGeoIP
    type: geoip
    description: Test Alias with type GeoIP
    content:
        - CH
        - DE

- name: Create an MAC Alias with the content FF:FF:FF:FF:FF
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeMAC
    type: macaddress
    statistics: false
    description: Test Alias with type MAC
    content: FF:FF:FF:FF:FF:FF

- name: Create a BGP ASN Alias with the content 65001 and protocol IPv4
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeBGPASN_ipv4
    type: bgpasn
    protocol: IPv4
    statistics: false
    description: Test Alias with type BGPASN with the content 65001 and protocol IPv4
    content: 65001

- name: Create an OPNVPNGROUP Alias with the content admins
  puzzle.opnsense.firewall_alias:
    name: TestAliasTypeOPNVPNGROUP
    type: opnvpngroup
    statistics: false
    description: Test Alias with type OPNVPNGROUP
    content: admins
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
'''
# fmt: on
from typing import Optional

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_alias_utils import (
    FirewallAlias,
    FirewallAliasSet,
)

ANSIBLE_MANAGED: str = "[ ANSIBLE ]"


def main():
    """Main module execution entry point."""

    module_args = {
        "enabled": {"type": "bool", "required": False, "default": True},
        "name": {"type": "str", "required": True},
        "type": {
            "type": "str",
            "choices": [
                "host",
                "network",
                "port",
                "url",
                "urltable",
                "geoip",
                "networkgroup",
                "macaddress",
                "bgpasn",
                "dynamicipv6host",
                "opnvpngroup",
                "internal",
                "external",
            ],
            "required": True,
        },
        "content": {"type": "list", "elements": "str", "required": False},
        "protocol": {
            "type": "list",
            "elements": "str",
            "required": False,
            "choices": ["IPv4", "IPv6", ""],
        },
        "statistics": {"type": "bool", "required": False, "default": False},
        "description": {"type": "str", "required": False},
        "refreshfrequency": {"type": "dict", "required": False},
        "interface": {"type": "str", "required": False},
        "state": {
            "type": "str",
            "required": False,
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
    description: Optional[str] = module.params["description"]

    if description and ANSIBLE_MANAGED not in description:
        description = f"{ANSIBLE_MANAGED} - {description}"
    else:
        description = ANSIBLE_MANAGED

    module.params["description"] = description

    ansible_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
        module.params
    )

    ansible_alias_state: str = module.params.get("state")

    with FirewallAliasSet() as alias_set:

        if ansible_alias_state == "present":
            alias_set.add_or_update(ansible_alias)
        else:
            # ansible_rule_state == "absent" since it is the only
            # alternative allowed in the module params
            alias_set.delete(ansible_alias)

        if alias_set.changed:
            result["diff"] = alias_set.diff
            result["changed"] = True
            alias_set.save()
            result["opnsense_configure_output"] = alias_set.apply_settings()
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
