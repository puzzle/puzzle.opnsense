#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""interfaces_configuration module: Module to configure OPNsense interface settings"""

# pylint: disable=duplicate-code
# pylint: disable=C0302
__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''
---
author:
  - Kyle Hammond (@kdhlab)
module: interfaces_configuration
version_added: "1.2.1"
short_description: This module can be used to configure assigned interface settings
description:
  - Module to configure interface settings for OPNsense.
options:
  identifier:
    description:
      - Technical identifier of the interface, used by hasync for example.
    type: str
    required: False
  adv_dhcp6_authentication_statement_algorithm:
    description:
      - Algorithm used for DHCPv6 authentication.
    type: str
    required: False
    aliases: ["dhcp6_authentication_algorithm"]
  adv_dhcp6_authentication_statement_authname:
    description:
      - Authentication name for DHCPv6.
    type: str
    required: False
    aliases: ["dhcp6_authentication_authname"]
  adv_dhcp6_authentication_statement_protocol:
    description:
      - Protocol used for DHCPv6 authentication.
    type: str
    required: False
    aliases: ["dhcp6_authentication_protocol"]
  adv_dhcp6_authentication_statement_rdm:
    description:
      - RDM for DHCPv6 authentication.
    type: str
    required: False
    aliases: ["dhcp6_authentication_rdm"]
  adv_dhcp6_config_advanced:
    description:
      - Enable advanced DHCPv6 configuration.
    type: bool
    required: False
    aliases: ["dhcp6_config_advanced"]
  adv_dhcp6_config_file_override:
    description:
      - Override DHCPv6 configuration file.
    type: bool
    required: False
    aliases: ["dhcp6_config_file_override"]
  adv_dhcp6_config_file_override_path:
    description:
      - Path to override DHCPv6 configuration file.
    type: str
    required: False
    aliases: ["dhcp6_config_file_override_path"]
  adv_dhcp6_id_assoc_statement_address:
    description:
      - DHCPv6 ID association address.
    type: str
    required: False
    aliases: ["dhcp6_id_assoc_address"]
  adv_dhcp6_id_assoc_statement_address_enable:
    description:
      - Enable DHCPv6 ID association address.
    type: bool
    required: False
    aliases: ["dhcp6_id_assoc_address_enable"]
  adv_dhcp6_id_assoc_statement_address_id:
    description:
      - ID for DHCPv6 ID association address.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_address_id"]
  adv_dhcp6_id_assoc_statement_address_pltime:
    description:
      - Preferred lifetime for DHCPv6 ID association address.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_address_pltime"]
  adv_dhcp6_id_assoc_statement_address_vltime:
    description:
      - Valid lifetime for DHCPv6 ID association address.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_address_vltime"]
  adv_dhcp6_id_assoc_statement_prefix:
    description:
      - DHCPv6 ID association prefix.
    type: str
    required: False
    aliases: ["dhcp6_id_assoc_prefix"]
  adv_dhcp6_id_assoc_statement_prefix_enable:
    description:
      - Enable DHCPv6 ID association prefix.
    type: bool
    required: False
    aliases: ["dhcp6_id_assoc_prefix_enable"]
  adv_dhcp6_id_assoc_statement_prefix_id:
    description:
      - ID for DHCPv6 ID association prefix.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_prefix_id"]
  adv_dhcp6_id_assoc_statement_prefix_pltime:
    description:
      - Preferred lifetime for DHCPv6 ID association prefix.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_prefix_pltime"]
  adv_dhcp6_id_assoc_statement_prefix_vltime:
    description:
      - Valid lifetime for DHCPv6 ID association prefix.
    type: int
    required: False
    aliases: ["dhcp6_id_assoc_prefix_vltime"]
  adv_dhcp6_interface_statement_information_only_enable:
    description:
      - Enable information-only mode for DHCPv6 interface.
    type: bool
    required: False
    aliases: ["dhcp6_interface_info_only_enable"]
  adv_dhcp6_interface_statement_request_options:
    description:
      - Request options for DHCPv6 interface.
    type: str
    required: False
    aliases: ["dhcp6_interface_request_options"]
  adv_dhcp6_interface_statement_script:
    description:
      - Script for DHCPv6 interface.
    type: str
    required: False
    aliases: ["dhcp6_interface_script"]
  adv_dhcp6_interface_statement_send_options:
    description:
      - Send options for DHCPv6 interface.
    type: str
    required: False
    aliases: ["dhcp6_interface_send_options"]
  adv_dhcp6_key_info_statement_expire:
    description:
      - Expiration time for DHCPv6 key information.
    type: str
    required: False
    aliases: ["dhcp6_key_info_expire"]
  adv_dhcp6_key_info_statement_keyid:
    description:
      - Key ID for DHCPv6 key information.
    type: int
    required: False
    aliases: ["dhcp6_key_info_keyid"]
  adv_dhcp6_key_info_statement_keyname:
    description:
      - Key name for DHCPv6 key information.
    type: str
    required: False
    aliases: ["dhcp6_key_info_keyname"]
  adv_dhcp6_key_info_statement_realm:
    description:
      - Realm for DHCPv6 key information.
    type: str
    required: False
    aliases: ["dhcp6_key_info_realm"]
  adv_dhcp6_key_info_statement_secret:
    description:
      - Secret for DHCPv6 key information.
    type: str
    required: False
    aliases: ["dhcp6_key_info_secret"]
  adv_dhcp6_prefix_interface_statement_sla_len:
    description:
      - SLA length for DHCPv6 prefix.
    type: int
    required: False
    aliases: ["dhcp6_prefix_sla_len"]
  adv_dhcp_config_advanced:
    description:
      - Enable advanced DHCP configuration.
    type: bool
    required: False
    aliases: ["dhcp_config_advanced"]
  adv_dhcp_config_file_override:
    description:
      - Override DHCP configuration file.
    type: bool
    required: False
    aliases: ["dhcp_config_file_override"]
  adv_dhcp_config_file_override_path:
    description:
      - Path to override DHCP configuration file.
    type: str
    required: False
    aliases: ["dhcp_config_file_override_path"]
  adv_dhcp_option_modifiers:
    description:
      - Modifiers for DHCP options.
    type: str
    required: False
    aliases: ["dhcp_option_modifiers"]
  adv_dhcp_pt_backoff_cutoff:
    description:
      - Backoff cutoff time for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_backoff_cutoff"]
  adv_dhcp_pt_initial_interval:
    description:
      - Initial interval for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_initial_interval"]
  adv_dhcp_pt_reboot:
    description:
      - Reboot time for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_reboot"]
  adv_dhcp_pt_retry:
    description:
      - Retry interval for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_retry"]
  adv_dhcp_pt_select_timeout:
    description:
      - Select timeout for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_select_timeout"]
  adv_dhcp_pt_timeout:
    description:
      - Timeout for DHCP.
    type: int
    required: False
    aliases: ["dhcp_pt_timeout"]
  adv_dhcp_pt_values:
    description:
      - Values for DHCP.
    type: str
    required: False
    aliases: ["dhcp_pt_values"]
  adv_dhcp_request_options:
    description:
      - Request options for DHCP.
    type: str
    required: False
    aliases: ["dhcp_request_options"]
  adv_dhcp_required_options:
    description:
      - Required options for DHCP.
    type: str
    required: False
    aliases: ["dhcp_required_options"]
  adv_dhcp_send_options:
    description:
      - Send options for DHCP.
    type: str
    required: False
    aliases: ["dhcp_send_options"]
  alias_address:
    description:
      - Alias address.
    type: str
    required: False
  alias_subnet:
    description:
      - Alias subnet.
    type: int
    required: False
  descr:
    description:
      - Description of the interface.
    type: str
    required: False
    aliases: ["description"]
  dhcp6_ia_pd_len:
    description:
      - Length of DHCPv6 IA_PD.
    type: int
    required: False
  dhcp6_prefix_id:
    description:
      - ID for DHCPv6 prefix.
    type: int
    required: False
  dhcp6_ifid:
    description:
      - IFID for DHCPv6.
    type: str
    required: False
  dhcp6vlanprio:
    description:
      - VLAN priority for DHCPv6.
    type: int
    required: False
    aliases: ["dhcp6_vlan_prio"]
  dhcphostname:
    description:
      - Hostname for DHCP.
    type: str
    required: False
    aliases: ["dhcp_hostname"]
  dhcprejectfrom:
    description:
      - Reject from DHCP.
    type: str
    required: False
    aliases: ["dhcp_reject_from"]
  dhcpvlanprio:
    description:
      - VLAN priority for DHCP.
    type: int
    required: False
    aliases: ["dhcp_vlan_prio"]
  disablechecksumoffloading:
    description:
      - Disable checksum offloading.
    type: bool
    required: False
    aliases: ["disable_checksum_offloading"]
  disablelargereceiveoffloading:
    description:
      - Disable large receive offloading.
    type: bool
    required: False
    aliases: ["disable_large_receive_offloading"]
  disablesegmentationoffloading:
    description:
      - Disable segmentation offloading.
    type: bool
    required: False
    aliases: ["disable_segmentation_offloading"]
  disablevlanhwfilter:
    description:
      - Disable VLAN hardware filter.
    type: bool
    required: False
    aliases: ["disable_vlan_hw_filter"]
  gateway:
    description:
      - Gateway.
    type: str
    required: False
    aliases: ["ipv4_gateway"]
  gateway_6rd:
    description:
      - 6RD gateway.
    type: str
    required: False
  gatewayv6:
    description:
      - IPv6 gateway.
    type: str
    required: False
    aliases: ["ipv6_gateway"]
  hw_settings_overwrite:
    description:
      - Overwrite hardware settings.
    type: bool
    required: False
  if:
    description:
      - Opnsense Device.
    type: str
    required: False
    aliases: ["device"]
  ipaddr:
    description:
      - IP address.
    type: str
    aliases: ["ipv4_address"]
  ipaddrv6:
    description:
      - IPv6 address.
    type: str
    aliases: ["ipv6_address"]
  media:
    description:
      - Media type.
    type: str
    required: False
    aliases: ["media"]
  mediaopt:
    description:
      - Media option.
    type: str
    required: False
    aliases: ["media_option"]
  mss:
    description:
      - Maximum segment size.
    type: int
    required: False
  mtu:
    description:
      - Maximum transmission unit.
    type: int
    required: False
  prefix_6rd:
    description:
      - 6RD prefix.
    type: str
    required: False
  prefix_6rd_v4addr:
    description:
      - IPv4 address for 6RD prefix.
    type: str
    required: False
  prefix_6rd_v4plen:
    description:
      - IPv4 prefix length for 6RD.
    type: int
    required: False
  spoofmac:
    description:
      - Spoof MAC address.
    type: str
    required: False
    aliases: ["mac_address"]
  track6_interface:
    description:
      - Track6 interface.
    type: str
    required: False
  track6_prefix_id:
    description:
      - Track6 prefix ID.
    type: int
    required: False
  track6_ifid:
    description:
      - Track6 IFID.
    type: str
    required: False
  subnet:
    description:
      - IPv4 Subnet mask in CIDR notation.
    type: int
    required: False
    when: "ipaddr"
    aliases: ["ipv4_subnet"]
  subnet6:
    description:
      - IPv6 Subnet mask in CIDR notation.
    type: int
    when: "ipaddr6"
    required: False
    aliases: ["ipv6_subnet"]
  state:
    description:
      - State of the interface configuration.
    type: str
    required: False
    choices: ["present", "absent"]
    default: "present"
requirements:
  - "python >= 2.7"
  - "ansible >= 2.9"
seealso:
  - name: OPNsense Interfaces Documentation
    description: Complete documentation for OPNsense interfaces.
    link: https://docs.opnsense.org/manual/interfaces.html
'''

EXAMPLES = r'''
- name: Assign Vagrant interface to device em4
  puzzle.opnsense.interfaces_configuration:
    identifier: "VAGRANT"
    if: "em4"

- name: Create new assignment
  puzzle.opnsense.interfaces_configuration:
    identifier: "lan"
    if: "vtnet1"
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

import ipaddress
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils import (  # pylint: disable=C0301
    InterfacesSet,
    InterfaceConfiguration,
    OPNSenseDeviceNotFoundError,
    OPNSenseDeviceAlreadyAssignedError,
    OPNSenseGetInterfacesError,
)


def validate_ipaddr_and_subnet(ipaddr, subnet):
    """
    Validates the given IP address and subnet.

    Args:
        ipaddr (str): The IP address to validate.
        subnet (str): The subnet to validate.

    Returns:
        tuple: A tuple containing the validated IP address and subnet.

    Raises:
        ValueError: If the IP address or subnet is invalid.
    """
    choices = ["none", "dhcp", "dhcp6", "pppoe"]
    if ipaddr in choices:
        return ipaddr, None
    try:
        if subnet is None:
            raise ValueError("Subnet must be provided when ipaddr is an IP address.")
        try:
            ip = ipaddress.ip_address(ipaddr)
            ip_network = ipaddress.ip_network(f"{ip}/{subnet}", strict=False)
        except ValueError as exc:
            raise ValueError("Invalid IPv4 Address.") from exc
        return ip, ip_network.prefixlen
    except ValueError as e:
        raise ValueError(f"Invalid value for ipaddr or subnet: {e}") from e


# Function to convert aliases to base arguments
def convert_aliases(args, alias_map):
    """
    Converts any module arguments that are aliases into the base argument.

    Args:
        args (dict): The dictionary of arguments to convert.
        alias_map (dict): The dictionary mapping aliases to base arguments.

    Returns:
        dict: The dictionary with aliases converted to base arguments.
    """
    converted_args = {}
    for key, value in args.items():
        base_key = alias_map.get(key, key)
        converted_args[base_key] = value
    return converted_args


def filter_explicitly_set_params(params, module_args):
    """
    Filters out parameters that are not explicitly set by the user.

    Args:
        params (dict): The dictionary of parameters to filter.
        module_args (dict): The dictionary of module arguments with their default values.

    Returns:
        dict: The dictionary with only explicitly set parameters.
    """
    explicitly_set_params = {}
    for key, value in params.items():
        if key in module_args and params[key] != module_args[key].get("default", None):
            explicitly_set_params[key] = value
    return explicitly_set_params


def main():
    """
    Main function of the interfaces_configuration module
    """

    module_args = {
        "identifier": {
            "type": "str",
            "description": "Technical identifier of the interface, used by hasync for example",
        },
        "adv_dhcp6_authentication_statement_algorithm": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_authentication_algorithm"],
        },
        "adv_dhcp6_authentication_statement_authname": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_authentication_authname"],
        },
        "adv_dhcp6_authentication_statement_protocol": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_authentication_protocol"],
        },
        "adv_dhcp6_authentication_statement_rdm": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_authentication_rdm"],
        },
        "adv_dhcp6_config_advanced": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp6_config_advanced"],
        },
        "adv_dhcp6_config_file_override": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp6_config_file_override"],
        },
        "adv_dhcp6_config_file_override_path": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_config_file_override_path"],
        },
        "adv_dhcp6_id_assoc_statement_address": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_id_assoc_address"],
        },
        "adv_dhcp6_id_assoc_statement_address_enable": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp6_id_assoc_address_enable"],
        },
        "adv_dhcp6_id_assoc_statement_address_id": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_address_id"],
        },
        "adv_dhcp6_id_assoc_statement_address_pltime": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_address_pltime"],
        },
        "adv_dhcp6_id_assoc_statement_address_vltime": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_address_vltime"],
        },
        "adv_dhcp6_id_assoc_statement_prefix": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_id_assoc_prefix"],
        },
        "adv_dhcp6_id_assoc_statement_prefix_enable": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp6_id_assoc_prefix_enable"],
        },
        "adv_dhcp6_id_assoc_statement_prefix_id": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_prefix_id"],
        },
        "adv_dhcp6_id_assoc_statement_prefix_pltime": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_prefix_pltime"],
        },
        "adv_dhcp6_id_assoc_statement_prefix_vltime": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_id_assoc_prefix_vltime"],
        },
        "adv_dhcp6_interface_statement_information_only_enable": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp6_interface_info_only_enable"],
        },
        "adv_dhcp6_interface_statement_request_options": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_interface_request_options"],
        },
        "adv_dhcp6_interface_statement_script": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_interface_script"],
        },
        "adv_dhcp6_interface_statement_send_options": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_interface_send_options"],
        },
        "adv_dhcp6_key_info_statement_expire": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_key_info_expire"],
        },
        "adv_dhcp6_key_info_statement_keyid": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_key_info_keyid"],
        },
        "adv_dhcp6_key_info_statement_keyname": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_key_info_keyname"],
        },
        "adv_dhcp6_key_info_statement_realm": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_key_info_realm"],
        },
        "adv_dhcp6_key_info_statement_secret": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp6_key_info_secret"],
        },
        "adv_dhcp6_prefix_interface_statement_sla_len": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_prefix_sla_len"],
        },
        "adv_dhcp_config_advanced": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp_config_advanced"],
        },
        "adv_dhcp_config_file_override": {
            "type": "bool",
            "required": False,
            "aliases": ["dhcp_config_file_override"],
        },
        "adv_dhcp_config_file_override_path": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_config_file_override_path"],
        },
        "adv_dhcp_option_modifiers": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_option_modifiers"],
        },
        "adv_dhcp_pt_backoff_cutoff": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_backoff_cutoff"],
        },
        "adv_dhcp_pt_initial_interval": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_initial_interval"],
        },
        "adv_dhcp_pt_reboot": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_reboot"],
        },
        "adv_dhcp_pt_retry": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_retry"],
        },
        "adv_dhcp_pt_select_timeout": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_select_timeout"],
        },
        "adv_dhcp_pt_timeout": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_pt_timeout"],
        },
        "adv_dhcp_pt_values": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_pt_values"],
        },
        "adv_dhcp_request_options": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_request_options"],
        },
        "adv_dhcp_required_options": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_required_options"],
        },
        "adv_dhcp_send_options": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_send_options"],
        },
        "alias_address": {
            "type": "str",
            "required": False,
            "aliases": ["alias_address"],
        },
        "alias_subnet": {"type": "int", "required": False, "aliases": ["alias_subnet"]},
        "blockprivate": {
            "type": "bool",
            "required": False,
            "aliases": ["block_private"],
        },
        "blockbogons": {"type": "bool", "required": False, "aliases": ["block_bogons"]},
        "descr": {"type": "str", "required": False, "aliases": ["description"]},
        "dhcp6_ia_pd_len": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_ia_pd_len"],
        },
        "dhcp6_prefix_id": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_prefix_id"],
        },
        "dhcp6_ifid": {"type": "str", "required": False, "aliases": ["dhcp6_ifid"]},
        "dhcp6vlanprio": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp6_vlan_prio"],
        },
        "dhcphostname": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_hostname"],
        },
        "dhcprejectfrom": {
            "type": "str",
            "required": False,
            "aliases": ["dhcp_reject_from"],
        },
        "dhcpvlanprio": {
            "type": "int",
            "required": False,
            "aliases": ["dhcp_vlan_prio"],
        },
        "disablechecksumoffloading": {
            "type": "bool",
            "required": False,
            "aliases": ["disable_checksum_offloading"],
        },
        "disablelargereceiveoffloading": {
            "type": "bool",
            "required": False,
            "aliases": ["disable_large_receive_offloading"],
        },
        "disablesegmentationoffloading": {
            "type": "bool",
            "required": False,
            "aliases": ["disable_segmentation_offloading"],
        },
        "disablevlanhwfilter": {
            "type": "bool",
            "required": False,
            "aliases": ["disable_vlan_hw_filter"],
        },
        "enable": {"type": "bool", "required": False, "aliases": ["enabled"]},
        "gateway": {"type": "str", "required": False, "aliases": ["ipv4_gateway"]},
        "gateway_6rd": {
            "type": "str",
            "required": False,
        },
        "gatewayv6": {"type": "str", "required": False, "aliases": ["ipv6_gateway"]},
        "hw_settings_overwrite": {
            "type": "bool",
            "required": False,
        },
        "if": {"type": "str", "required": False, "aliases": ["device"]},
        "ipaddr": {"type": "str", "required": False, "aliases": ["ipv4_address"]},
        "ipaddr6": {"type": "str", "required": False, "aliases": ["ipv6_address"]},
        "lock": {"type": "bool", "required": False, "aliases": ["locked"]},
        "media": {
            "type": "str",
            "required": False,
        },
        "mediaopt": {"type": "str", "required": False, "aliases": ["media_option"]},
        "mss": {
            "type": "int",
            "required": False,
        },
        "mtu": {
            "type": "int",
            "required": False,
        },
        "prefix_6rd": {
            "type": "str",
            "required": False,
        },
        "prefix_6rd_v4addr": {
            "type": "str",
            "required": False,
        },
        "prefix_6rd_v4plen": {
            "type": "int",
            "required": False,
        },
        "spoofmac": {"type": "str", "required": False, "aliases": ["mac_address"]},
        "track6_interface": {
            "type": "str",
            "required": False,
        },
        "track6_prefix_id": {
            "type": "int",
            "required": False,
        },
        "track6_ifid": {
            "type": "str",
            "required": False,
        },
        "subnet": {
            "type": "int",
            "required": False,
            "when": "ipaddr",
            "aliases": ["ipv4_subnet"],
        },
        "subnet6": {
            "type": "int",
            "required": False,
            "when": "ipaddr6",
            "aliases": ["ipv6_subnet"],
        },
        "state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
            "default": "present",
        },
    }

    # Create the alias map
    alias_map = {}
    for key, value in module_args.items():
        if "aliases" in value:
            for alias in value["aliases"]:
                alias_map[alias] = key

    # Initialize the Ansible module
    module = AnsibleModule(argument_spec=module_args)

    # Convert aliases to base arguments
    params = convert_aliases(module.params, alias_map)

    # Filter out parameters that are not explicitly set by the user
    params = filter_explicitly_set_params(params, module_args)

    # ensure state is present by default
    params["state"] = params.get("state", "present")

    # Process the converted arguments
    result = {}
    if params.get("ipaddr"):
        # Validate ipaddr and subnet parameters
        try:
            params["ipaddr"], params["subnet"] = validate_ipaddr_and_subnet(
                params["ipaddr6"], params["subnet6"]
            )  # pylint: disable=C0301
        except ValueError as e:
            module.fail_json(msg=str(e))

    if params.get("ipaddr6"):
        # Validate ipaddr and subnet parameters
        try:
            params["ipaddr6"], params["subnet6"] = validate_ipaddr_and_subnet(
                params["ipaddr6"], params["subnet6"]
            )  # pylint: disable=C0301
        except ValueError as e:
            module.fail_json(msg=str(e))

    interface_configuration = InterfaceConfiguration.from_ansible_module_params(params)
    print(interface_configuration)
    with InterfacesSet() as interfaces_set:
        try:
            existing_interface = interfaces_set.find(identifier=params["identifier"])

            if params["state"] == "absent":
                if existing_interface:
                    interfaces_set.remove(existing_interface)
                    result["changed"] = True
                else:
                    result["changed"] = False
            else:
                interfaces_set.add_or_update(interface_configuration)
                result["changed"] = interfaces_set.changed

        except OPNSenseDeviceNotFoundError as e:
            module.fail_json(msg=str(e))
        except OPNSenseDeviceAlreadyAssignedError as e:
            module.fail_json(msg=str(e))
        except OPNSenseGetInterfacesError as e:
            module.fail_json(msg=str(e))

        if interfaces_set.changed and not module.check_mode:
            interfaces_set.save()
            result["opnsense_configure_output"] = interfaces_set.apply_settings()

            for cmd_result in result["opnsense_configure_output"]:
                if cmd_result["rc"] != 0:
                    module.fail_json(
                        msg="Apply of the OPNsense settings failed",
                        details=cmd_result,
                    )

        module.exit_json(**result)


if __name__ == "__main__":
    main()
