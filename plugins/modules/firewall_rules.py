#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Copyright: (c) 2023, Puzzle ITC, Fabio Bertagna <bertagna@puzzle.ch>, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""Firewall rules module: Read, write, edit operations for firewall rules """

__metaclass__ = type


# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''

module: firewall_rules

short_description: This module is used to manage OPNSense firewall rules.

version_added: "0.0.2"

description: This module is used to manage OPNSense firewall rules

options:
    action:
        description: Choose what to do with packets that match the criteria specified below.
        choices: [ pass, block, reject ]
        required: true
        default: pass
        type: str
    disabled:
        description: Set this option to disable this rule without removing it from the list.
        required: false
        default: false
        type: bool
    quick:
        description: If a packet matches a rule specifying quick, then that rule is considered the last matching rule and the specified action is taken.
        When a rule does not have quick enabled, the last matching rule wins.
        required: false
        default: true
        type: bool
    interface:
        description: Choose on which interface packets must come in to match this rule.
        required: true
        type: str
    direction:
        description: Direction of the traffic. Traffic IN is coming into the firewall interface, while traffic OUT is going out of the firewall interface.
        In visual terms: [Source] -> IN -> [Firewall] -> OUT -> [Destination]. The default policy is to filter inbound traffic,
        which means the policy applies to the interface on which the traffic is originally received by the firewall from the source.
        This is more efficient from a traffic processing perspective. In most cases, the default policy will be the most appropriate.
        choices: [in, out]
        required: false
        default: in
        type: str
    protocol:
        description: Choose which IP protocol this rule should match.
        choices:
          - any
          - tcp
          - udp
          - tcp/udp
          - icmp
          - esp
          - ah
          - gre
          - igmp
          - pim
          - ospf
          - ggp
          - ipencap
          - st2
          - cbt
          - egp
          - igp
          - bbn-rcc
          - nvp
          - pup
          - argus
          - emcon
          - xnet
          - chaos
          - mux
          - dcn
          - hmp
          - prm
          - xns-idp
          - trunk-1
          - trunk-2
          - leaf-1
          - leaf-2
          - rdp
          - irtp
          - iso-tp4
          - netblt
          - mfe-nsp
          - merit-inp
          - dccp
          - 3pc
          - idpr
          - xtp
          - ddp
          - idpr-cmtp
          - tp++
          - il
          - ipv6
          - sdrp
          - idrp
          - rsvp
          - dsr
          - bna
          - i-nlsp
          - swipe
          - narp
          - mobile
          - tlsp
          - skip
          - ipv6-icmp
          - cftp
          - sat-expak
          - kryptolan
          - rvd
          - ippc
          - sat-mon
          - visa
          - ipcv
          - cpnx
          - cphb
          - wsn
          - pvp
          - br-sat-mon
          - sun-nd
          - wb-mon
          - wb-expak
          - iso-ip
          - vmtp
          - secure-vmtp
          - vines
          - ttp
          - nsfnet-igp
          - dgp
          - tcf
          - eigrp
          - sprite-rpc
          - larp
          - mtp
          - ax.25
          - ipip
          - micp
          - scc-sp
          - etherip
          - encap
          - gmtp
          - ifmp
          - pnni
          - aris
          - scps
          - qnx
          - a/n
          - ipcomp
          - snp
          - compaq-peer
          - ipx-in-ip
          - carp
          - pgm
          - l2tp
          - ddx
          - iatp
          - stp
          - srp
          - uti
          - smp
          - sm
          - ptp
          - isis
          - crtp
          - crudp
          - sps
          - pipe
          - sctp
          - fc
          - rsvp-e2e-ignore
          - udplite
          - mpls-in-ip
          - manet
          - hip
          - shim6
          - wesp
          - rohc
          - pfsync
          - divert
        required: false
        default: any
        type: str
    source_invert:
        description: Use this option to invert the sense of the match.
        required: false
        default: false
        type: bool
    source_ip:
        description: CIDR notation of the source IP of the rule. Can either be a single host or a network.
        required: false
        default: any
        type: str
    source_port:
        description: Source port, being a number from 0 to 65535 or 'any'.
        required: false
        type: str
    target_invert:
        description: Use this option to invert the sense of the match.
        required: false
        default: false
        type: bool
    target_ip:
        description: CIDR notation of the target IP of the rule. Can either be a single host or a network.
        required: false
        default: any
        type: str
    target_port:
        description: Target port, being a number from 0 to 65535 or 'any'.
        required: false
        default: any
        type: str
    log:
        description: Log packets that are handled by this rule. Hint: the firewall has limited local log space.
        Don't turn on logging for everything. If you want to do a lot of logging, consider using a remote syslog server.
        required: false
        default: false
        type: bool
    category:
        description: You may enter or select a category here to group firewall rules
        required: false
        type: str
    description:
        description: Description for the rule.
        required: false
        type: str
    state:
        description: Weather rule should be added or removed.
        required: false
        type: str
        default: present
        choices: [present, absent]

author:
    - Fabio Bertagna (@dongiovanni83)
    - Kilian Soltermann (@killuuuhh)
'''

EXAMPLES = r"""
- name: Block SSH in LAN Network
  puzzleitc.opnsense.firewall_rules:
    interface: 'LAN'
    target_port: 22
    action: 'block'

- name: Allow all access from RFC1918 networks to this host
  puzzleitc.opnsense.firewall_rules:
    interface: 'eth0'
    action: 'pass'
    source_ip: 192.168.0.0/16
"""

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
from typing import Optional

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_rules_utils import (
    FirewallRuleSet,
    FirewallRule,
    FirewallRuleProtocol,
)


ANSIBLE_MANAGED: str = "[ ANSIBLE ]"


def main():
    module_args = {
        "action": {
            "type": "str",
            "required": True,
            "choices": ["pass", "block", "reject"],
            "default": "pass",
        },
        "disabled": {"type": "bool", "required": False, "default": False},
        "quick": {"type": "bool", "required": False, "default": True},
        "interface": {"type": "str", "required": True},
        "direction": {
            "type": "str",
            "required": False,
            "default": "in",
            "choices": ["in", "out"],
        },
        "ipprotocol": {
            "type": "str",
            "required": False,
            "default" : "inet",
            "choices": [ "inet", "inet6", "inet46" ]

        },
        "protocol": {
            "type": "str",
            "required": False,
            "default": "any",
            "choices": FirewallRuleProtocol.as_list(),
        },
        "source_invert": {"type": "bool", "required": False, "default": False},
        "source_ip": {"type": "str", "required": False, "default": "any"},
        "source_port": {"type": "str", "required": False, "default": "any"},
        "target_invert": {"type": "bool", "required": False, "default": False},
        "target_ip": {"type": "str", "required": False, "default": "any"},
        "target_port": {"type": "str", "required": False, "default": "any"},
        "log": {"type": "bool", "required": False, "default": False},
        "category": {"type": "str", "required": False},
        "description": {"type": "str", "required": False},
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

    ansible_rule: FirewallRule = FirewallRule(...)  # TODO

    ansible_rule_state: str = module.params.get("state")

    with FirewallRuleSet() as rule_set:
        if ansible_rule_state == "present":
            rule_set.add_or_update(ansible_rule)
        elif ansible_rule_state == "absent":
            rule_set.delete(ansible_rule)
        else:
            raise ValueError("TEMP")  # TODO

        if rule_set.changed:
            result["diff"] = rule_set.diff
            result["changed"] = True
            rule_set.save()
            result["opnsense_configure_output"] = rule_set.apply_settings()
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
