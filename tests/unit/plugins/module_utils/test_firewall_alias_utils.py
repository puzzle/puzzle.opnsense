#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test suite for the firewall_alias module.
"""

# pylint: skip-file
import os
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_alias_utils import (
    OPNsenseContentValidationError,
    OPNsenseInterfaceNotFoundError,
    OPNsenseMaximumTableEntriesExceededError,
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
    etree_to_dict,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "firewall_alias": {
            "alias": "OPNsense/Firewall/Alias/aliases",
            "geoip": "OPNsense/Firewall/Alias/geoip",
            "php_requirements": [],
            "configure_functions": {},
        },
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "maximumtableentries": "system/maximumtableentries",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "interfaces_configuration": {
            "interfaces": "interfaces",
            "php_requirements": [],
            "configure_functions": {},
        },
    }
}

TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
     <system>
        <group>
            <name>admins</name>
            <description>System Administrators</description>
            <scope>system</scope>
            <gid>1999</gid>
            <member>0</member>
            <member>2004</member>
            <member>2005</member>
            <member>2006</member>
            <member>2009</member>
            <member>2010</member>
            <member>2014</member>
            <priv>page-all</priv>
        </group>
        <group>
            <name>test_group</name>
            <description>test_group</description>
            <scope>system</scope>
            <member>2004</member>
            <member>2021</member>
            <gid>2000</gid>
            <priv>page-all</priv>
        </group>
        <maximumtableentries>100000</maximumtableentries>
    </system>
    <interfaces>
        <wan>
            <if>em2</if>
            <ipaddr>dhcp</ipaddr>
            <dhcphostname/>
            <mtu/>
            <subnet/>
            <gateway/>
            <media/>
            <mediaopt/>
            <blockbogons>1</blockbogons>
            <ipaddrv6>dhcp6</ipaddrv6>
            <dhcp6-ia-pd-len>0</dhcp6-ia-pd-len>
            <blockpriv>1</blockpriv>
            <descr>WAN</descr>
            <lock>1</lock>
        </wan>
        <lan>
            <if>em1</if>
            <descr>LAN</descr>
            <enable>1</enable>
            <lock>1</lock>
            <spoofmac/>
            <blockbogons>1</blockbogons>
            <ipaddr>192.168.56.10</ipaddr>
            <subnet>21</subnet>
            <ipaddrv6>track6</ipaddrv6>
            <track6-interface>wan</track6-interface>
            <track6-prefix-id>0</track6-prefix-id>
        </lan>
        <opt1>
            <if>em3</if>
            <descr>DMZ</descr>
            <spoofmac/>
            <lock>1</lock>
        </opt1>
        <opt2>
            <if>em0</if>
            <descr>VAGRANT</descr>
            <enable>1</enable>
            <lock>1</lock>
            <spoofmac/>
            <ipaddr>dhcp</ipaddr>
            <dhcphostname/>
            <alias-address/>
            <alias-subnet>32</alias-subnet>
            <dhcprejectfrom/>
            <adv_dhcp_pt_timeout/>
            <adv_dhcp_pt_retry/>
            <adv_dhcp_pt_select_timeout/>
            <adv_dhcp_pt_reboot/>
            <adv_dhcp_pt_backoff_cutoff/>
            <adv_dhcp_pt_initial_interval/>
            <adv_dhcp_pt_values>SavedCfg</adv_dhcp_pt_values>
            <adv_dhcp_send_options/>
            <adv_dhcp_request_options/>
            <adv_dhcp_required_options/>
            <adv_dhcp_option_modifiers/>
            <adv_dhcp_config_advanced/>
            <adv_dhcp_config_file_override/>
        <adv_dhcp_config_file_override_path/>
        </opt2>
        <lo0>
            <internal_dynamic>1</internal_dynamic>
            <descr>Loopback</descr>
            <enable>1</enable>
            <if>lo0</if>
            <ipaddr>127.0.0.1</ipaddr>
            <ipaddrv6>::1</ipaddrv6>
            <subnet>8</subnet>
            <subnetv6>128</subnetv6>
            <type>none</type>
            <virtual>1</virtual>
        </lo0>
        <openvpn>
            <internal_dynamic>1</internal_dynamic>
            <enable>1</enable>
            <if>openvpn</if>
            <descr>OpenVPN</descr>
            <type>group</type>
            <virtual>1</virtual>
            <networks/>
        </openvpn>
    </interfaces>
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
                <content>CF
DZ
AG</content>
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
            <alias uuid="cbdf5dfb-7121-4db2-bdf4-e46be8acf026">
                <enabled>1</enabled>
                <name>bgp_test_none</name>
                <type>asn</type>
                <proto/>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>123456</content>
                <categories/>
                <description>bgp_test_none</description>
            </alias>
            <alias uuid="f37cc8be-2533-42f0-8581-65ef1df5e5b4">
                <enabled>1</enabled>
                <name>bgp_test_ipv4</name>
                <type>asn</type>
                <proto>IPv4</proto>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>123456</content>
                <categories/>
                <description>bgp_test_ipv4</description>
          </alias>
          <alias uuid="ccab3bc6-004c-4587-ac8c-72f191c2f461">
                <enabled>1</enabled>
                <name>bgp_test_ipv6</name>
                <type>asn</type>
                <proto>IPv6</proto>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>123456</content>
                <categories/>
                <description>bgp_test_ipv6</description>
          </alias>
          <alias uuid="7289199d-3b53-478d-b827-2ef10c112a5e">
                <enabled>1</enabled>
                <name>bgp_test_ipv4_ipv6</name>
                <type>asn</type>
                <proto>IPv4,IPv6</proto>
                <interface/>
                <counters>0</counters>
                <updatefreq/>
                <content>123456</content>
                <categories/>
                <description>bgp_test_ipv4_ipv6</description>
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
    assert test_alias.proto == IPProtocol.NONE.value
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
    assert test_alias.proto == IPProtocol.IPv4
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
        counters=False,
        updatefreq=None,
        content="10.0.0.1",
        description="host_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[0]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
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
        counters=False,
        updatefreq=None,
        content=["CF", "DZ", "AG"],
        description="geoip_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[5]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
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
        counters=False,
        updatefreq="2",
        content="www.puzzle.ch",
        description="url_table_test",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[4]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_bgpasn_none():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="cbdf5dfb-7121-4db2-bdf4-e46be8acf026",
        enabled="1",
        name="bgp_test_none",
        type=FirewallAliasType.BGPASN.value,
        proto=None,
        interface=None,
        counters=False,
        categories=None,
        content="123456",
        description="bgp_test_none",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        11
    ]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_bgpasn_ipv4():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="f37cc8be-2533-42f0-8581-65ef1df5e5b4",
        enabled="1",
        name="bgp_test_ipv4",
        type=FirewallAliasType.BGPASN.value,
        proto="IPv4",
        interface=None,
        counters=False,
        categories=None,
        content="123456",
        description="bgp_test_ipv4",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        12
    ]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_bgpasn_ipv6():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="ccab3bc6-004c-4587-ac8c-72f191c2f461",
        enabled="1",
        name="bgp_test_ipv6",
        type=FirewallAliasType.BGPASN.value,
        proto="IPv6",
        interface=None,
        counters=False,
        categories=None,
        content="123456",
        description="bgp_test_ipv6",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        13
    ]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


def test_firewall_alias_to_etree_with_bgpasn_ipv4_ipv6():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="7289199d-3b53-478d-b827-2ef10c112a5e",
        enabled="1",
        name="bgp_test_ipv4_ipv6",
        type=FirewallAliasType.BGPASN.value,
        proto="IPv4,IPv6",
        interface=None,
        counters=False,
        categories=None,
        content="123456",
        description="bgp_test_ipv4_ipv6",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        14
    ]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
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
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.HOSTS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.content == ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"]
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_refreshfrequency_float():
    """
    Test FirewallAlias instantiation form refreshfrequency(float) Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "urltable",
        "description": "Test Alias",
        "enabled": True,
        "content": ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"],
        "refreshfrequency": {"days": 2, "hours": 47},
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.URLTABLES
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq == float(3.958333333333333)
    assert new_alias.content == ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"]
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_refreshfrequency_float():
    """
    Test FirewallAlias instantiation form refreshfrequency(int) Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "urltable",
        "description": "Test Alias",
        "enabled": True,
        "content": ["__lan_network", "8.8.8.8-9.9.9.9", "192.168.0.0"],
        "refreshfrequency": {"days": 1, "hours": 48},
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.URLTABLES
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq == 3
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


def test_firewall_alias_from_ansible_module_params_macaddress():
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
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.MACADDRESS
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.content == "FF:FF:FF:FF:FF"
    assert new_alias.description == "Test Alias"


def test_firewall_alias_from_ansible_module_params_empty_content():
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


def test_firewall_alias_from_ansible_module_params_list_content():
    """
    Test FirewallAlias instantiation form geoip content Ansible parameters.
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


def test_firewall_alias_from_ansible_module_params_asn_list_content():
    """
    Test FirewallAlias instantiation form protocol content Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "bgpasn",
        "description": "Test Alias",
        "enabled": True,
        "protocol": ["IPv4", "IPv6"],
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == FirewallAliasType.BGPASN
    assert new_alias.proto == IPProtocol.IPv4_IPv6
    assert new_alias.interface is None
    assert new_alias.counters is False
    assert new_alias.updatefreq is None
    assert new_alias.description == "Test Alias"


############################
# content_type validations #
############################


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_host_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "host",
        "description": "Test Alias",
        "enabled": True,
        "content": ["8.8.8.8-9.9.9.9", "TestHost", "192.168.0.0"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.HOSTS
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["8.8.8.8-9.9.9.9", "TestHost", "192.168.0.0"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_host_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
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

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert (
            "Entry 192.168.0.0/24 is not a valid hostname, IP address or range."
            in str(excinfo.value)
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_OPNsenseMaximumTableEntriesExceededError(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with invalid Ansible parameters.
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "host",
        "description": "Test Alias",
        "enabled": True,
        "content": ["Test"],
    }

    with pytest.raises(OPNsenseMaximumTableEntriesExceededError) as excinfo:
        with FirewallAliasSet(sample_config_path) as alias_set:
            alias_set.maximumtableentries = 0
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

    assert str(excinfo.value) == "MaximumTableEntries exceeded!"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_network_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "network",
        "description": "Test Alias",
        "enabled": True,
        "content": ["192.168.0.0/24", "!192.168.1.0/24"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.NETWORKS
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["192.168.0.0/24", "!192.168.1.0/24"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_network_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "network",
        "description": "Test Alias",
        "enabled": True,
        "content": ["Test_Network"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Entry Test_Network is not a network." in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_networkgroup_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "networkgroup",
        "description": "Test Alias",
        "enabled": True,
        "content": ["network_test", "network_group_test"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.NETWORKGROUP
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["network_test", "network_group_test"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_networkgroup_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with not valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "networkgroup",
        "description": "Test Alias",
        "enabled": True,
        "content": ["Test_Group"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Entry Test_Group is not of type NetworkAlias or InternalAlias." in str(
            excinfo.value
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_port_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "port",
        "description": "Test Alias",
        "enabled": True,
        "content": ["30:90", "22", "5000:5002"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.PORTS
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["30:90", "22", "5000:5002"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_port_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
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

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Entry !30 is not a valid port number." in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_macaddress_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "macaddress",
        "description": "Test Alias",
        "enabled": True,
        "content": ["08:5b:0c:a3:f1:9e", "1a:2b:3c:4d:5e:6f"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.MACADDRESS
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["08:5b:0c:a3:f1:9e", "1a:2b:3c:4d:5e:6f"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_macaddress_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "macaddress",
        "description": "Test Alias",
        "enabled": True,
        "content": ["test_mac", "!test_mac"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Entry test_mac is not a valid (partial) MAC address." in str(
            excinfo.value
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_bgpasn_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    # protocol isn't a list!!
    test_params: dict = {
        "name": "bgp_test_ipv4",
        "type": "bgpasn",
        "description": "Test Alias",
        "enabled": True,
        "content": ["123456"],
        "protocol": ["IPv4"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="bgp_test_ipv4")

        assert new_alias.enabled is True
        assert new_alias.name == "bgp_test_ipv4"
        assert new_alias.type == FirewallAliasType.BGPASN
        assert new_alias.proto == IPProtocol.IPv4
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["123456"]
        assert new_alias.description == "Test Alias"

        alias_set.save()

    test_element = new_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        12
    ]

    # description has changed
    assert not elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_bgpasn_list_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """

    test_params: dict = {
        "name": "bgp_test_ipv4_ipv6",
        "type": "bgpasn",
        "description": "bgp_test_ipv4_ipv6",
        "enabled": True,
        "content": ["123456"],
        "protocol": ["IPv4", "IPv6"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

        alias_set.add_or_update(new_alias)

        # assert not alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="bgp_test_ipv4_ipv6")

        assert new_alias.enabled is True
        assert new_alias.name == "bgp_test_ipv4_ipv6"
        assert new_alias.type == FirewallAliasType.BGPASN
        assert new_alias.proto == IPProtocol.IPv4_IPv6
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["123456"]
        assert new_alias.description == "bgp_test_ipv4_ipv6"

        alias_set.save()

    test_element = new_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = test_etree_opnsense.find("OPNsense/Firewall/Alias/aliases")[
        14
    ]

    assert elements_equal(test_element, orig_alias), (
        f"{etree_to_dict(test_element)}\n" f"{etree_to_dict(orig_alias)}"
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_bgpasn_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "bgpasn",
        "description": "Test Alias",
        "enabled": True,
        "content": ["test_asn", "!test_asn"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Entry test_asn is not a valid ASN." in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_dynamicipv6host_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "dynamicipv6host",
        "description": "Test Alias",
        "enabled": True,
        "interface": "WAN",
        "content": [
            "::1000",
            "::abcd:1234:5678:abcd",
            "::aaaa:bbbb:cccc:0001",
            "::1234:5678:abcd:1234",
        ],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.DYNAMICIPV6HOST
        assert new_alias.proto is None
        assert new_alias.interface == "WAN"
        assert new_alias.counters is False
        assert new_alias.content == [
            "::1000",
            "::abcd:1234:5678:abcd",
            "::aaaa:bbbb:cccc:0001",
            "::1234:5678:abcd:1234",
        ]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_dynamicipv6host_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "dynamicipv6host",
        "description": "Test Alias",
        "interface": "WAN",
        "enabled": True,
        "content": ["2001::10", "2002::10"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert (
            "Entry 2001::10 is not a valid partial IPv6 address definition (e.g. ::1000)."
            in str(excinfo.value)
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_dynamicipv6host_interface_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "dynamicipv6host",
        "description": "Test Alias",
        "interface": "test_interface",
        "enabled": True,
        "content": ["::1000", "::abcd:1234:5678:abcd"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseInterfaceNotFoundError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "interface test_interface was not found on the device" in str(
            excinfo.value
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_opnvpngroup_validation(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation with valid Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "opnvpngroup",
        "description": "Test Alias",
        "enabled": True,
        "content": ["admins", "test_group"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)
        alias_set.add_or_update(new_alias)

        assert alias_set.changed

        alias_set.save()

    with FirewallAliasSet(sample_config_path) as new_alias_set:
        new_alias: FirewallAlias = new_alias_set.find(name="test_alias")

        assert new_alias.enabled is True
        assert new_alias.name == "test_alias"
        assert new_alias.type == FirewallAliasType.OPNVPNGROUP
        assert new_alias.proto is None
        assert new_alias.interface is None
        assert new_alias.counters is False
        assert new_alias.content == ["1999", "2000"]
        assert new_alias.description == "Test Alias"

        alias_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_opnvpngroup_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "opnvpngroup",
        "description": "Test Alias",
        "enabled": True,
        "content": ["test_group_2", "test_group_3"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert "Group test_group_2 was not found on the Instance." in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_from_ansible_module_params_with_content_type_geoip_validation_error(
    mocked_version_utils: MagicMock, sample_config_path
):
    """
    Test FirewallAlias instantiation form exlusion content list Ansible parameters.
    :return:
    """
    test_params: dict = {
        "name": "test_alias",
        "type": "geoip",
        "description": "Test Alias",
        "enabled": True,
        "content": ["CH", "DE"],
    }

    with FirewallAliasSet(sample_config_path) as alias_set:
        with pytest.raises(OPNsenseContentValidationError) as excinfo:
            new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(
                test_params
            )
            alias_set.add_or_update(new_alias)
            alias_set.save()

        assert (
            "In order to use GeoIP, you need to configure a source in the GeoIP settings tab"
            in str(excinfo.value)
        )


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
        assert len(alias_set._aliases) == 15

        alias_set.save()
