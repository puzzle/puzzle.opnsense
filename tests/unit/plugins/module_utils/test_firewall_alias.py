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
            "alias": "Firewall/Alias/aliases",
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
        <Firewall>
        <Alias version="1.0.0">
            <geoip>
            <url/>
            </geoip>
            <aliases>
                <alias uuid="18467880-8247-438e-82be-0fa3ef54b0b7">
                    <enabled>1</enabled>
                    <name>test</name>
                    <type>host</type>
                    <proto/>
                    <interface/>
                    <counters>0</counters>
                    <updatefreq/>
                    <content>__lan_network</content>
                    <description>ba</description>
                </alias>
                <alias uuid="bc264802-e579-4439-a21c-3337076db635">
                    <enabled>1</enabled>
                    <name>test_entry_2</name>
                    <type>network</type>
                    <proto/>
                    <interface/>
                    <counters>0</counters>
                    <updatefreq/>
                    <content>sshlockout</content>
                    <description>test_entry_2  description</description>
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
    Test xml parsing to FirewallAlias dataclass instance.
    :return:
    """
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_alias: Element = list(list(test_etree_opnsense)[0][0])[1][0]
    test_alias: FirewallAlias = FirewallAlias.from_xml(test_etree_alias)

    assert test_alias.uuid == "18467880-8247-438e-82be-0fa3ef54b0b7"
    assert test_alias.enabled == True
    assert test_alias.name == "test"
    assert test_alias.type == "host"
    assert test_alias.proto is None
    assert test_alias.interface is None
    assert test_alias.counters == "0"
    assert test_alias.updatefreq is None
    assert test_alias.content == "__lan_network"
    assert test_alias.description == "ba"


def test_firewall_alias_to_etree():
    """
    Test FirewallAlias instance to ElementTree Element conversion.
    :return:
    """
    test_alias: FirewallAlias = FirewallAlias(
        uuid="18467880-8247-438e-82be-0fa3ef54b0b7",
        enabled="1",
        name="test",
        type="host",
        proto=None,
        interface=None,
        counters="0",
        updatefreq=None,
        content="__lan_network",
        description="ba",
    )

    test_element = test_alias.to_etree()

    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    orig_alias: Element = list(list(test_etree_opnsense)[0][0])[1][0]

    assert elements_equal(test_element, orig_alias), (
        f"{xml_utils.etree_to_dict(test_element)}\n" f"{xml_utils.etree_to_dict(orig_alias)}"
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
        "content": "__lan_network",
    }

    new_alias: FirewallAlias = FirewallAlias.from_ansible_module_params(test_params)

    assert new_alias.enabled is True
    assert new_alias.name == "test_alias"
    assert new_alias.type == "host"
    assert new_alias.proto is None
    assert new_alias.interface is None
    assert new_alias.counters == "0"
    assert new_alias.updatefreq is None
    assert new_alias.content == "__lan_network"
    assert new_alias.description == "Test Alias"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_firewall_alias_set_load_simple_rules(mocked_version_utils: MagicMock, sample_config_path):
    """
    Test correct loading of FirewallAliasSet from XML config without changes.
    """
    with FirewallAliasSet(sample_config_path) as alias_set:
        assert len(alias_set._aliases) == 2
        alias_set.save()
