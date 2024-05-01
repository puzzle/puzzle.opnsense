# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the ansible_collections.puzzle.opnsense.plugins.modules.test_system_high_availability_settings"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import subprocess
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
import os
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from ansible_collections.puzzle.opnsense.plugins.modules.system_high_availability_settings import (
    check_hasync_node,
    synchronize_states,
    synchronize_interface,
    synchronize_peer_ip,
    remote_system_synchronization,
    services_to_synchronize
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


import pytest


TEST_VERSION_MAP = {
    "OPNsense Test": {
        "system_high_availability_settings":
        {
            # Add other mappings here
            "parent_node": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "Aliases": "hasync/synchronizealiases",
            "Auth Servers": "hasync/synchronizeauthservers",
            "Captive Portal": "hasync/synchronizecaptiveportal",
            "Certificates": "hasync/synchronizecerts",
            "Cron": "hasync/syncronizecron",
            "DHCPD": "hasync/syncronizedhcp",
            "DHCPDv6": "hasync/syncronizedhcpdv6",
            "DHCPv4: Relay": "hasync/syncronizedhcrelay6",
            "DHCPv6: Relay": "hasync/syncronizedhcrelay",
            "Dashboard": "hasync/synchronizewidgets",
            "Dnsmasq DNS": "hasync/synchronizednsforwarder",
            "FRR": "hasync/",
            "Firewall Categories": "hasync/synchronizecategories",
            "Firewall Groups": "hasync/synchronizeifgroups",
            "Firewall Log Templates": "hasync/synchronizelvtemplate",
            "Firewall Rules": "hasync/synchronizerules",
            "Firewall Schedules": "hasync/synchronizeschedules",
            "IPsec": "hasync/synchronizeipsec",
            "Intrusion Detection": "hasync/synchronizesuricata",
            "Kea DHCP": "hasync/synchronizekea",
            "Monit System Monitoring": "hasync/synchronizemonit",
            "NAT": "hasync/synchronizenat",
            "Netflow / Insight": "hasync/synchronizesyslog",
            "Network Time": "hasync/synchronizentpd",
            "OpenSSH": "hasync/syncronizessh",
            "OpenVPN": "hasync/synchronizeopenvpn",
            "Shaper": "hasync/synchronizeshaper",
            "Static Routes": "hasync/synchronizestaticroutes",
            "System Tunables": "hasync/synchronizesysctl",
            "Unbound DNS": "hasync/synchronizednsresolver",
            "User and Groups": "hasync/syncronizeusers",
            "Virtual IPs": "hasync/synchronizevirtualip",
            "Web GUI": "hasync/syncronizewebgui",
            "WireGuard": "hasync/synchronizewireguard",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                ],
            "configure_functions": {

            },
        },
    }
}


XML_CONFIG_EMPTY: str = """<?xml version="1.0"?>
    <opnsense>
    </opnsense>
    """

XML_CONFIG: str = """<?xml version="1.0"?>
    <opnsense>
      <hasync>
        <pfsyncinterface>lan</pfsyncinterface>
        <synchronizetoip/>
        <username/>
        <password/>
      </hasync>
    </opnsense>
    """


@pytest.fixture(scope="function")
def sample_config(request):
    """
    Fixture that creates a temporary file with a test XML configuration.
    The file  is used in the tests.

    Returns:
    - str: The path to the temporary file.
    """
    with patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",  # pylint: disable=line-too-long
        return_value="OPNsense Test",
    ), patch.dict(VERSION_MAP, TEST_VERSION_MAP, clear=True):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(request.param.encode())
            temp_file.flush()
        with OPNsenseModuleConfig(
            module_name="system_high_availability_settings",
            config_context_names=["system_high_availability_settings"],
            path=temp_file.name,
            check_mode=True,
        ) as config:
            yield config

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG_EMPTY], indirect=True)
def test_check_hasync_node(mocked_version_utils: MagicMock, sample_config):
    assert sample_config.get("parent_node") is None
    check_hasync_node(sample_config)
    assert sample_config.get("parent_node") is not None
    assert sample_config.get("synchronize_interface").text == "lan"

    assert sample_config.get("synchronize_config_to_ip") is not None
    assert sample_config.get("synchronize_config_to_ip").text is None

    assert sample_config.get("remote_system_username") is not None
    assert sample_config.get("remote_system_username").text is None

    assert sample_config.get("remote_system_password") is not None
    assert sample_config.get("remote_system_password").text is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG], indirect=True)
def test_synchronize_states(mocked_version_utils: MagicMock, sample_config):
    synchronize_states(sample_config, False)
    assert sample_config.get("synchronize_states") is None
    synchronize_states(sample_config, True)
    assert sample_config.get("synchronize_states").text == "on"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG], indirect=True)
def test_synchronize_interface(mocked_version_utils: MagicMock, sample_config):
    synchronize_interface(sample_config, "opt1")
    assert sample_config.get("synchronize_interface").text == "opt1"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG], indirect=True)
def test_synchronize_peer_ip(mocked_version_utils: MagicMock, sample_config):
    synchronize_peer_ip(sample_config, "240.0.0.240")
    assert sample_config.get("synchronize_peer_ip").text == "240.0.0.240"
    synchronize_peer_ip(sample_config, None)
    assert sample_config.get("synchronize_peer_ip") is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG], indirect=True)
def test_remote_system_synchronization(mocked_version_utils: MagicMock, sample_config):
    remote_system_synchronization(sample_config, None, "test", "vagrant")
    assert sample_config.get("synchronize_config_to_ip") is not None
    assert sample_config.get("synchronize_config_to_ip").text is None
    assert sample_config.get("remote_system_username").text == "test"
    assert sample_config.get("remote_system_password").text == "vagrant"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize('sample_config', [XML_CONFIG], indirect=True)
def test_services_to_synchronize(mocked_version_utils: MagicMock, sample_config):
    services = ["Aliases", "Auth Servers", "Captive Portal", "Certificates"]
    services_to_synchronize(sample_config, services)
    assert sample_config.get("Aliases").text == "on"
    assert sample_config.get("Cron") is None

    services_to_synchronize(sample_config, [])
    assert sample_config.get("Cron") is None
    assert sample_config.get("Aliases") is None

    with pytest.raises(ValueError):
        services_to_synchronize(sample_config, ["Aliases", "bababooey"])
