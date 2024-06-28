#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024,  Yoan Müller <ymueller@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""system_high_availability_settings module: Module to configure general OPNsense system settings"""

__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off

DOCUMENTATION = r'''
---
author:
  - Yoan Müller (@LuminatiHD)
module: system_high_availability_settings
version_added: "1.2.0"
short_description: Configure high availability settings
description:
  - Module to configure high availability system settings
options:
  disable_preempt:
    description: "When this device is configured as CARP master it will try to switch to master when powering up, this option will keep this one slave if there already is a master on the network. A reboot is required to take effect."
    type: bool
    default: false
  disconnect_dialup_interfaces:
    description: "When this device is configured as CARP backup it will disconnect all PPP type interfaces and try to reconnect them when becoming master again."
    type: bool
    default: false
  synchronize_states:
    description: "pfsync transfers state insertion, update, and deletion messages between firewalls. Each firewall sends these messages out via multicast on a specified interface, using the PFSYNC protocol ([IP Protocol 240](https://www.openbsd.org/faq/pf/carp.html)). It also listens on that interface for similar messages from other firewalls, and imports them into the local state table. This setting should be enabled on all members of a failover group."  # nopep8
    type: bool
    default: false
  synchronize_interface:
    description: "If Synchronize States is enabled, it will utilize this interface for communication."
    type: str
    required: true
  synchronize_peer_ip:
    description: "Setting this option will force pfsync to synchronize its state table to this IP address. The default is directed multicast. "
    type: str
    required: false
  synchronize_config_to_ip:
    description: "IP address of the firewall to which the selected configuration sections should be synchronized."
    type: str
    required: false
  remote_system_username:
    description: "Enter the web GUI username of the system entered above for synchronizing your configuration."
    type: str
    required: false
  remote_system_password:
    description: "Enter the web GUI password of the system entered above for synchronizing your configuration."
    type: str
    required: false
  services_to_synchronize:
    description: "List of config items to synchronize to the other firewall."
    type: list
    elements: str
    required: false
'''

EXAMPLES = r'''
---
- name: Enable State sync via CARP
  puzzle.opnsense.system_high_availability_settings:
    synchronize_interface: "sync"
    synchronize_states: true

- name: Synchronize Configuration Settings
  puzzle.opnsense.system_high_availability_settings:
    synchronize_interface: LAN
    synchronize_config_to_ip: 192.168.1.3
    remote_system_username: root
    remote_system_password: v3rys3cure
    services_to_synchronize:
      - "Dashboard"
      - "Users and Groups"
      - "Auth Servers"
      - "Certificates"
      - "Virtual IPs"
      - "OpenVPN"
      - "Firewall Groups"
      - "Firewall Rules"
      - "Firewall Schedules"
      - "Aliases"
      - "NAT"
'''
# pylint: disable=duplicate-code
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
# pylint: enable=duplicate-code
# fmt: on
from typing import Optional, List, Dict
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    UnsupportedModuleSettingError,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_assignments_utils import (
    OPNSenseGetInterfacesError,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    opnsense_utils,
)


def validate_ipv4(ipaddr: str) -> bool:
    """
    Check if the given string is an IPv4 address
    """
    digits = ipaddr.split(".")
    if len(digits) != 4:
        return False
    for num in digits:
        if not (num.isdigit() and int(num) < 256):
            return False
    return True


def check_hasync_node(config: OPNsenseModuleConfig) -> None:
    """
    When an opnsense instance is created, the hasync block does not exist at all.
    This function checks if the opnsense/hasync exists in the tree. If not, it
    adds that parent node with the default settings (pfsyncinterface=LAN
    synchronize_config_to_ip, remote_system_username and remote_system_password all None)
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
    """
    if config.get("hasync") is None:
        ElementTree.SubElement(
            config._config_xml_tree,  # pylint: disable=W0212
            config._config_maps[  # pylint: disable=W0212
                "system_high_availability_settings"
            ]["hasync"],
        )
        # default settings when nothing is selected
        synchronize_interface(config, "lan")
        config.set(value=None, setting="synchronize_config_to_ip")
        config.set(value=None, setting="remote_system_username")
        config.set(value=None, setting="remote_system_password")


def disable_preempt(config: OPNsenseModuleConfig, setting: bool) -> None:
    """
    Handler function for the setting disable_preempt.
    Args:
        config (OPNsenseModuleConfig): The given Opnsense configuration
        setting (bool): The setting value
    """
    if setting and config.get("disable_preempt") is None:
        config.set(value="on", setting="disable_preempt")
    elif not setting and config.get("disable_preempt") is not None:
        config.get("hasync").remove(config.get("disable_preempt"))


def disconnect_dialup_interfaces(config: OPNsenseModuleConfig, setting: bool) -> None:
    """
    Handler function for the setting disconnect_dialup_interfaces.
    Args:
        config (OPNsenseModuleConfig): The given Opnsense configuration
        setting (bool): The setting value
    """
    if setting and config.get("disconnect_dialup_interfaces") is None:
        config.set(value="on", setting="disconnect_dialup_interfaces")
    elif not setting and config.get("disconnect_dialup_interfaces") is not None:
        config.get("hasync").remove(config.get("disconnect_dialup_interfaces"))


def synchronize_states(config: OPNsenseModuleConfig, setting: bool) -> None:
    """
    Handler function for the synchronize_states setting.
    Args:
        config (OPNsenseModuleConfig): The given Opnsense configuration
        setting (bool): The setting value
    """
    if setting and config.get("synchronize_states") is None:
        config.set(value="on", setting="synchronize_states")
    elif not setting and config.get("synchronize_states") is not None:
        config.get("hasync").remove(config.get("synchronize_states"))


def get_configured_interface_with_descr() -> Dict[str, str]:
    """
    Get all interfaces that are allowed to be used for synchronize_interface
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
    """
    # https://github.com/opnsense/core/blob/7d212f3e5d9eb2456acf2165987dd850cd78c710/src/etc/inc/util.inc#L822
    # load requirements
    php_requirements = [
        "/usr/local/etc/inc/interfaces.inc",
        "/usr/local/etc/inc/util.inc",
        "/usr/local/etc/inc/config.inc",
    ]
    php_command = """
                foreach (get_configured_interface_with_descr() as $key => $item) {
                    echo $key.':'.$item.',';
                }
                """

    # run php function
    result = opnsense_utils.run_command(
        php_requirements=php_requirements,
        command=php_command,
    )

    # check for stderr
    if result.get("stderr"):
        raise OPNSenseGetInterfacesError("error encountered while getting interfaces")

    # parse list
    interfaces = dict(
        (item.strip().split(":"))
        for item in result.get("stdout").split(",")
        if item.strip() and item.strip() != "None"
    )

    # check parsed list length
    if len(interfaces) < 1:
        raise OPNSenseGetInterfacesError(
            "error encountered while getting interfaces, no interfaces available"
        )

    return interfaces


def synchronize_interface(config: OPNsenseModuleConfig, sync_interface: str) -> None:
    """
    Handler function for the synchronize_interface setting
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
        sync_interface (bool): If synchronize_states is enabled,
                               it will utilize this interface for communication.
    """
    interfaces = {"lo0": "Loopback"}
    interfaces.update(get_configured_interface_with_descr())
    for ident, desc in interfaces.items():
        if sync_interface.lower() in (ident.lower(), desc.lower()):
            config.set(ident, "synchronize_interface")
            return
    raise ValueError(
        f"'{sync_interface}' is not a valid interface. "
        + "If the interface exists, ensure it is enabled and also not virtual."
    )


def synchronize_peer_ip(config: OPNsenseModuleConfig, peer_ip: str) -> None:
    """
    Handler function for the synchronize_peer_ip setting
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
        peer_ip: PFsync will sync to this IP address.
    """
    if peer_ip:
        if not validate_ipv4(peer_ip):
            raise ValueError(
                "Setting synchronize_peer_ip has to be a valid IPv4 address"
            )
        config.set(value=peer_ip, setting="synchronize_peer_ip")
    elif not peer_ip and config.get("synchronize_peer_ip") is not None:
        config.get("hasync").remove(config.get("synchronize_peer_ip"))


def remote_system_synchronization(
    config: OPNsenseModuleConfig,
    remote_backup_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
) -> None:
    """
    Handler function for the settings synchronize_config_to_ip,
    remote_system_username and remote_system_password.
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
        remote_backup_url (Optional[str]): Synchronize your settings to this URL
        username (Optional[str]): Username for logging in to the remote firewall
        password (Optional[str]): Password for logging in to the remote firewall
    """
    if any((remote_backup_url, username, password)):
        config.set(value=remote_backup_url, setting="synchronize_config_to_ip")
        config.set(value=username, setting="remote_system_username")
        config.set(value=password, setting="remote_system_password")


def plugins_xmlrpc_sync() -> Dict[str, str]:
    """
    Get all services on the firewall which can even be synced
    """
    # https://github.com/opnsense/core/blob/66c684b2c66d26000129bfb161c6cbafe4175dc8/src/etc/inc/plugins.inc#L355
    php_requirements = ["/usr/local/etc/inc/plugins.inc"]
    php_command = """
                foreach (plugins_xmlrpc_sync() as $key => $item) {
                    echo $key.','.$item['description'].'\n';
                }
                """

    # run php function
    result = opnsense_utils.run_command(
        php_requirements=php_requirements,
        command=php_command,
    )

    # check for stderr
    if result.get("stderr"):
        raise OPNSenseGetInterfacesError("error encountered while getting services")
    allowed_services = dict(
        service.split(",") for service in result.get("stdout_lines")
    )
    return allowed_services


def services_to_synchronize(
    config: OPNsenseModuleConfig, sync_services: List[str]
) -> None:
    """
    Handler function for the setting services_to_synchronize.
    Args:
        config (OPNsenseModuleConfig): The configuration for the opnsense firewall
        sync_services (List[str]): A list of services that should be synchronized
    """
    if isinstance(sync_services, str):
        sync_services = [sync_services]

    # Opnsense has a helper function called plugins_xmlrpc_sync, which returns all services
    # installed on Opnsense that can be synced. They are returned as a dictionary. Here an
    # example as to how this dictionary would look like:
    # {
    #   "cron": "Cron",
    #   "dhcrelay": "DHCPv4: Relay",
    #   "virtualip": "Virtual IPs",
    #   "sysctl": "System Tunables",
    # }
    # Or in short, the key is how the services will be referenced in the config, while the
    # "description" is how the service is referenced in the GUI. For this reason, when given
    # a service we try to identify it both by checking it against the ID's of all services as
    # well as all the descriptions.

    allowed_services = plugins_xmlrpc_sync()
    # add all to-be-synced services that aren't already in the config
    for service in sync_services:
        # Try to match the service by service_id
        if service in allowed_services.keys():
            service_id = service
            service_description = allowed_services[service]
        # Try to match the service by its name in the GUI
        elif service in allowed_services.values():
            # Invert the dictionary, i.e. look up the id of the service by its description. No two
            # services have the same description, as none of them do the exact same thing, so there
            # is no need to worry about collisions.
            service_id = {v: k for k, v in allowed_services.items()}[service]
            service_description = service

        # could not match the service, so doesn't exist on the instance or misspelled.
        else:
            raise ValueError(
                f"Service {service} could not be found in your Opnsense installation. "
                + f"These are all the available services: {', '.join(allowed_services.values())}."
            )

        # The services get written into the config as follows:
        # If a service should get synced, say cron, you'll find a line in the config that
        # looks like this:
        # <synchronizecron>on</synchronizecron>
        # In general, if a service should get synced, we add an element to the config with the name
        # "synchronize{service_id}", with the value "on".
        # (see https://github.com/opnsense/core/blob/24f36bf3323bdb08894a8619ab8e2b22ed557539/src/www/system_hasync.php#L55) # pylint: disable=line-too-long
        # If a service shouldn't get synced, the element is removed from the config entirely.
        service_xml_element_name = f"synchronize{service_id}"
        if config.get("hasync").find(service_xml_element_name) is None:
            xml_elem = Element(service_xml_element_name)
            xml_elem.text = "on"
            config.get("hasync").append(xml_elem)

    # remove all services in the config that shouldn't be synced.
    for service_id, service_description in allowed_services.items():
        service_xml_elem = config.get("hasync").find(f"synchronize{service_id}")
        if (
            service_id not in sync_services
            and service_description not in sync_services
            and service_xml_elem is not None
        ):
            config.get("hasync").remove(service_xml_elem)


def main():
    """
    Main function of the system_high_availability_settings module
    """

    module_args = {
        "disable_preempt": {"type": "bool", "default": False},
        "disconnect_dialup_interfaces": {"type": "bool", "default": False},
        "synchronize_states": {"type": "bool", "default": False},
        "synchronize_interface": {"type": "str", "required": True},
        "synchronize_peer_ip": {"type": "str", "required": False},
        "synchronize_config_to_ip": {"type": "str", "required": False},
        "remote_system_username": {"type": "str", "required": False},
        "remote_system_password": {"type": "str", "required": False, "no_log": True},
        "services_to_synchronize": {
            "type": "list",
            "required": False,
            "elements": "str",
        },
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[
            [
                "disable_preempt",
                "disconnect_dialup_interfaces",
                "synchronize_states",
                "synchronize_interface",
                "synchronize_peer_ip",
                "synchronize_config_to_ip",
                "remote_system_username",
                "remote_system_password",
                "services_to_synchronize",
            ],
        ],
    )
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    disable_preempt_param = module.params.get("disable_preempt")
    disconnect_dialup_interfaces_param = module.params.get(
        "disconnect_dialup_interfaces"
    )
    synchronize_states_param = module.params.get("synchronize_states")
    synchronize_interface_param = module.params.get("synchronize_interface")
    synchronize_peer_ip_param = module.params.get("synchronize_peer_ip")
    synchronize_config_to_ip_param = module.params.get("synchronize_config_to_ip")
    remote_system_username_param = module.params.get("remote_system_username")
    remote_system_password_param = module.params.get("remote_system_password")
    services_to_synchronize_param = module.params.get("services_to_synchronize")

    with OPNsenseModuleConfig(
        module_name="system_high_availability_settings",
        config_context_names=["system_high_availability_settings"],
        check_mode=module.check_mode,
    ) as config:
        check_hasync_node(config)
        remote_system_synchronization(
            config=config,
            remote_backup_url=synchronize_config_to_ip_param,
            username=remote_system_username_param,
            password=remote_system_password_param,
        )

        synchronize_states(config=config, setting=synchronize_states_param)
        disable_preempt(config=config, setting=disable_preempt_param)
        disconnect_dialup_interfaces(
            config=config, setting=disconnect_dialup_interfaces_param
        )

        if synchronize_interface_param:
            try:
                synchronize_interface(
                    config=config, sync_interface=synchronize_interface_param
                )
            except ValueError as error:
                module.fail_json(str(error))
            except OPNSenseGetInterfacesError as error:
                module.fail_json(
                    f"Encountered Error while trying to retrieve interfaces: {str(error)}"
                )

        if synchronize_peer_ip_param:
            try:
                synchronize_peer_ip(config=config, peer_ip=synchronize_peer_ip_param)
            except ValueError as error:
                module.fail_json(str(error))

        if services_to_synchronize_param is not None:
            try:
                services_to_synchronize(
                    config=config, sync_services=services_to_synchronize_param
                )
            except ValueError as error:
                module.fail_json(str(error))
            except UnsupportedModuleSettingError as error:
                module.fail_json(str(error))

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

        module.exit_json(**result)


if __name__ == "__main__":
    main()
