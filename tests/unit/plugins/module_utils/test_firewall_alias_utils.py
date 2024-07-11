#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Test suite for the firewall_alias module.
"""

import os
import sys
from tempfile import NamedTemporaryFile
from typing import Optional
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_alias_utils import (
    OPNsenseContentValidationError,
    IPProtocol,
    FirewallAliasType,
    FirewallAlias,
    FirewallAliasSet,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.xml_utils import (
    elements_equal,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "firewall_alias": {
            "alias": "OPNsense/Firewall/Alias/aliases",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": [],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
    }
}

TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
    <OPNsense>
        <Firewall>
        <Alias version="1.0.0">
            <geoip>
            <url/>
            </geoip>
            <aliases>
            <alias uuid="ad0fd5d4-6797-4521-9ee4-df3e16de31d0">
                <enabled>1</enabled>
                <name>host_test</name>
                <type>host</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>10.0.0.1</content>
                <description>host_test</description>
            </alias>
            <alias uuid="3fc15914-8492-4a67-b990-aefd08d1c6a4">
                <enabled>1</enabled>
                <name>network_test</name>
                <type>network</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>192.168.0.0</content>
                <description>network_test</description>
            </alias>
            <alias uuid="78fe9621-c4d0-4f1f-a1b7-55796b041089">
                <enabled>1</enabled>
                <name>port_test</name>
                <type>port</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>22</content>
                <description>port_test</description>
            </alias>
            <alias uuid="901a0b76-2054-4e3e-8319-74fa5a458d3e">
                <enabled>1</enabled>
                <name>url_test</name>
                <type>url</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>www.puzzle.ch</content>
                <description>url_test</description>
            </alias>
            <alias uuid="d17640f6-2b57-444b-8370-cbca1db6e612">
                <enabled>1</enabled>
                <name>url_table_test</name>
                <type>urltable</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq>2</updatefreq>
                <content>www.puzzle.ch</content>
                <description>url_table_test</description>
            </alias>
            <alias uuid="207ac163-9f71-4af2-9c50-937e4a92355e">
                <enabled>1</enabled>
                <name>geoip_test</name>
                <type>geoip</type>
                <proto>IPv4</proto>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>
                CF
                DZ
                AG
                </content>
                <description>geoip_test</description>
            </alias>
            <alias uuid="7e776c20-5658-45fb-924d-9fd833eae142">
                <enabled>1</enabled>
                <name>network_group_test</name>
                <type>networkgroup</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>host_test</content>
                <description>network_group_test</description>
            </alias>
            <alias uuid="51c62c88-603c-46e4-86b0-4bf382e94a51">
                <enabled>1</enabled>
                <name>macaddress_test</name>
                <type>mac</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>FF:FF:FF:FF:FF</content>
                <description>macaddress_test</description>
            </alias>
            <alias uuid="a32cac6d-c6d8-4c2c-8e88-bf4a6b787f67">
                <enabled>1</enabled>
                <name>dynamicipv6</name>
                <type>dynipv6host</type>
                <proto/>
                <interface>lan</interface>
                <counters>0</counters>
                <updatefreq/>
                <content>::1000</content>
                <description>dynamicipv6</description>
            </alias>
            <alias uuid="770afc89-c3e8-4090-b2c3-51372b290dfe">
                <enabled>1</enabled>
                <name>internal_test</name>
                <type>internal</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content/>
                <description>internal_test</description>
            </alias>
            <alias uuid="f5e7295e-88e6-46d0-8409-a68883456474">
                <enabled>1</enabled>
                <name>external_test</name>
                <type>external</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content/>
                <description>external_test</description>
            </alias>
            </aliases>
        </Alias>
        <Lvtemplate version="0.0.1">
            <templates/>
        </Lvtemplate>
        <Category version="1.0.0">
            <categories/>
        </Category>
        </Firewall>
    </OPNsense>
    </opnsense>
    """


@pytest.fixture(scope="function")
def sample_config_path(request):
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
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


def test_firewall_alias_from_xml():
    """
    Test xml parsing to FirewallAlias instance.
    :return:
    """
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_alias: Element = test_etree_opnsense.find(
        "OPNsense/Firewall/Alias/aliases"
    )[0]

    test_alias: FirewallAlias = FirewallAlias.from_xml(test_etree_alias)

    assert test_alias.uuid == "ad0fd5d4-6797-4521-9ee4-df3e16de31d0"
    assert test_alias.enabled is True
    assert test_alias.name == "host_test"
    assert test_alias.type == FirewallAliasType.HOSTS
    assert test_alias.proto is None
    assert test_alias.interface is None
    assert test_alias.counters is False
    assert test_alias.updatefreq is None
    assert test_alias.content == ["10.0.0.1"]
    assert test_alias.description == "host_test"


def test_firewall_alias_type_geoip_with_content_from_xml():
    """
    Test xml parsing to FirewallAlias geoip_with_content instance.
    :return:
    """
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_alias: Element = test_etree_opnsense.find(
        "OPNsense/Firewall/Alias/aliases"
    )[5]
    test_alias: FirewallAlias = FirewallAlias.from_xml(test_etree_alias)

    assert test_alias.uuid == "207ac163-9f71-4af2-9c50-937e4a92355e"
    assert test_alias.enabled is True
    assert test_alias.name == "geoip_test"
    assert test_alias.type == FirewallAliasType.GEOIP
    assert test_alias.proto == IPProtocol.IPv4.value
    assert test_alias.interface is None
    assert test_alias.counters is False
    assert test_alias.updatefreq is None
    assert test_alias.content == ["CF", "DZ", "AG"]


def test_firewall_alias_to_etree():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="ad0fd5d4-6797-4521-9ee4-df3e16de31d0",
        enabled="1",
        name="host_test",
        type=FirewallAliasType.HOSTS.value,
        proto=None,
        interface=None,
        counters="0",
        updatefreq=None,
        content="10.0.0.1",
        description="host_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[0]

    assert elements_equal(test_element, orig_alias), (
        f"{xml_utils.etree_to_dict(test_element)}\n"
        f"{xml_utils.etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_content():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="207ac163-9f71-4af2-9c50-937e4a92355e",
        enabled="1",
        name="geoip_test",
        type=FirewallAliasType.GEOIP,
        proto=IPProtocol.IPv4,
        interface=None,
        counters="0",
        updatefreq=None,
        content=["CF", "DZ", "AG"],
        description="geoip_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[5]

    assert elements_equal(test_element, orig_alias), (
        f"{xml_utils.etree_to_dict(test_element)}\n"
        f"{xml_utils.etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_updatefreq():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="d17640f6-2b57-444b-8370-cbca1db6e612",
        enabled="1",
        name="url_table_test",
        type=FirewallAliasType.URLTABLES.value,
        proto=None,
        interface=None,
        counters="0",
        updatefreq="2",
        content="www.puzzle.ch",
        description="url_table_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[4]

    assert elements_equal(test_element, orig_alias), (
        f"{xml_utils.etree_to_dict(test_element)}\n"
        f"{xml_utils.etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_from_ansible_module_params_simple():
    """
    Test FirewallAlias instantiation form simple Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "host",
        "description": "Test Alias",
        "enabled": True,
        "content": ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"],
        "refreshfrequency": 2,
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.HOSTS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq == 2
    assert new_alias.content == ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"]
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_network():
    """
    Test FirewallAlias instantiation form network Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "network",
        "description": "Test Alias",
        "enabled": True,
        "content": ["192.168.0.0/24", "!192.168.1.0/24"],
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.NETWORKS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.content == ["192.168.0.0/24", "!192.168.1.0/24"]
    assert new_alias.description == "Test Alias"


def atest_firewall_alias_from_ansible_module_params_macaddress():
    """
    Test FirewallAlias instantiation form macaddress Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "macaddress",
        "description": "Test Alias",
        "enabled": True,
        "content": "FF:FF:FF:FF:FF",
        "refreshfrequency": 2,
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.MACADDRESS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq == 2
    assert new_alias.content == "FF:FF:FF:FF:FF"
    assert new_alias.description == "Test Alias"


def atest_firewall_alias_from_ansible_module_params_empty_content():
    """
    Test FirewallAlias instantiation form empty content Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "host",
        "description": "Test Alias",
        "enabled": True,
        "content": "",
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.HOSTS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.content == ""
    assert new_alias.description == "Test Alias"


def atest_firewall_alias_from_ansible_module_params_exclusion_content():
    """
    Test FirewallAlias instantiation form empty content Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "network",
        "description": "Test Alias",
        "enabled": True,
        "content": "!192.168.1.0/24",
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.NETWORKS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.content == "!192.168.1.0/24"
    assert new_alias.description == "Test Alias"


def atest_firewall_alias_from_ansible_module_params_list_content():
    """
    Test FirewallAlias instantiation form empty content Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "geoip",
        "description": "Test Alias",
        "enabled": True,
        "content": ["CH", "DE"],
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.GEOIP
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.content == ["CH", "DE"]
    assert new_alias.description == "Test Alias"


def atest_firewall_alias_from_ansible_module_params_list_exclusion_content():
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "port",
        "description": "Test Alias",
        "enabled": True,
        "content": ["!30", "!34:40"],
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.PORTS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.content == ["!30", "!34:40"]
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_with_unknown_content_type_validation():
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "internal",
        "description": "Test Alias",
        "enabled": True,
        "content": "test_content",
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.INTERNAL
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.content == "test_content"
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_with_content_type_host_validation_error():
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "host",
        "description": "Test Alias",
        "enabled": True,
        "content": ["8.8.8.8-9.9.9.9", "192.168.0.0/24", "192.168.0.0"],
    }

    with pytest.raises(OPNsenseContentValidationError) as excinfo:

        FirewallAlias.from_ansible_module_params(test_params)

    assert "Entry 192.168.0.0/24 is not a valid hostname, IP address or range." in str(
        excinfo.value
    )


def test_firewall_alias_from_ansible_module_params_with_content_type_network_validation_error():
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "network",
        "description": "Test Alias",
        "enabled": True,
        "content": ["Test_Host"],
    }

    with pytest.raises(OPNsenseContentValidationError) as excinfo:

        FirewallAlias.from_ansible_module_params(test_params)

    assert "Entry Test_Host is not a network." in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_set_load_simple_rules(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test correct loading of FirewallAliasSet from XML config without changes.
    """
    with FirewallAliasSet(sample_config_path) as alias_set:
        assert len(alias_set._aliases) == 11

        alias_set.save()
