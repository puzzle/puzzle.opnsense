#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
import os
import re
from tempfile import NamedTemporaryFile
from typing import Optional
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
import hashlib

import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.xml_utils import (
    elements_equal,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.users_utils import User, UserSet
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "users": {
            "users": "system/user",
            "system": "system",
            "php_requirements": [
                "contrib/base32/Base32.php",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": [],
                },
            },
        },
    }
}

TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
        <system>
            <hostname>test_name</hostname>
            <test>test_name_2</test>
            <user>
                <password>$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O</password>
                <scope>user</scope>
                <name>vagrant</name>
                <descr>vagrant box management</descr>
                <expires />
                <authorizedkeys />
                <ipsecpsk />
                <otp_seed />
                <shell>/bin/sh</shell>
                <uid>1000</uid>
            </user>
        </system>
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


def test_user_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_user: Element = list(list(test_etree_opnsense)[0])[2]
    test_user: User = User.from_xml(test_etree_user)

    assert test_user.name == "vagrant"
    assert test_user.password == "$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O"
    assert test_user.scope == "user"
    assert test_user.descr == "vagrant box management"
    assert test_user.expires is None
    assert test_user.authorizedkeys is None
    assert test_user.ipsecpsk is None
    assert test_user.otp_seed is None
    assert test_user.shell == "/bin/sh"
    assert test_user.uid == "1000"


def test_user_to_etree():
    test_user: User = User(
        password="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
        scope="user",
        name="vagrant",
        descr="vagrant box management",
        shell="/bin/sh",
        uid="1000",
    )
    test_element = test_user.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_user: Element = list(list(orig_etree)[0])[2]

    assert xml_utils.elements_equal(test_element, orig_user)


def test_user_from_ansible_module_params_simple():
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "description": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }

    new_user: User = User.from_ansible_module_params(test_params)

    assert new_user.name == "vagrant"
    assert new_user.password == "vagrant"  # Verify hashed password
    assert new_user.scope == "user"
    assert new_user.descr == "vagrant box management"
    assert new_user.expires is None
    assert new_user.authorizedkeys is None
    assert new_user.ipsecpsk is None
    assert new_user.otp_seed is None
    assert new_user.shell == "/bin/sh"
    assert new_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_set_load_simple_rules(mocked_version_utils: MagicMock, sample_config_path):
    with UserSet(sample_config_path) as user_set:
        assert len(user_set._users) == 1
        user_set.save()


# def test_firewall_rule_from_xml_any_1():
#    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
#
#    test_etree_rule: Element = list(list(test_etree_opnsense)[0])[2]
#    test_rule: FirewallRule = FirewallRule.from_xml(test_etree_rule)
#
#    assert test_rule.uuid is None
#    assert test_rule.type == FirewallRuleAction.PASS
#    assert test_rule.interface == "opt2"
#    assert test_rule.ipprotocol == IPProtocol.IPv4
#    assert test_rule.statetype == FirewallRuleStateType.KEEP_STATE
#    assert test_rule.descr == "allow vagrant management"
#    assert test_rule.protocol is None
#    assert test_rule.source_port is None
#    assert test_rule.source_address is None
#    assert test_rule.source_network is None
#    assert not test_rule.source_not
#    assert test_rule.source_any
#    assert test_rule.destination_port is None
#    assert test_rule.destination_address is None
#    assert test_rule.destination_network is None
#    assert not test_rule.destination_not
#    assert test_rule.destination_any
#    assert test_rule.direction is FirewallRuleDirection.IN
#    assert not test_rule.disabled
#    assert not test_rule.log
#    assert test_rule.category is None
#    assert test_rule.quick
#
#
# def test_firewall_rule_to_etree():
#    test_rule: FirewallRule = FirewallRule(
#        interface="wan",
#        uuid="9c7ecb2c-49f3-4750-bc67-d5b666541999",
#        type=FirewallRuleAction.PASS,
#        descr="Allow SSH access",
#        ipprotocol=IPProtocol.IPv4,
#        protocol=FirewallRuleProtocol.TCP,
#        source_any=True,
#        destination_port="22",
#        destination_any=True,
#        statetype=FirewallRuleStateType.KEEP_STATE,
#    )
#
#    test_element = test_rule.to_etree()
#
#    orig_etree: Element = ElementTree.fromstring(TEST_XML)
#    orig_rule: Element = list(list(orig_etree)[0])[0]
#
#    assert xml_utils.elements_equal(test_element, orig_rule)
#
#
# def test_firewall_rule_from_ansible_module_params_simple():
#    test_params: dict = {
#        "action": "pass",
#        "interface": "wan",
#        "ipprotocol": "inet",
#        "description": "Allow SSH access",
#        "protocol": "tcp",
#        "source_ip": "any",
#        "target_ip": "any",
#        "target_port": "22",
#        "disabled": False,
#    }
#
#    new_rule: FirewallRule = FirewallRule.from_ansible_module_params(test_params)
#
#    assert new_rule.type == FirewallRuleAction.PASS
#    assert new_rule.interface == "wan"
#    assert new_rule.ipprotocol == IPProtocol.IPv4
#    assert new_rule.descr == "Allow SSH access"
#    assert new_rule.protocol == FirewallRuleProtocol.TCP
#    assert new_rule.source_any
#    assert new_rule.source_address is None
#    assert new_rule.source_port is None
#    assert not new_rule.source_not
#    assert new_rule.source_network is None
#    assert new_rule.destination_any
#    assert new_rule.destination_address is None
#    assert new_rule.destination_port == "22"
#    assert not new_rule.destination_not
#    assert new_rule.destination_network is None
#
#
# @patch(
#    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
#    return_value="OPNsense Test",
# )
# @patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
# def test_rule_set_load_simple_rules(mocked_version_utils: MagicMock, sample_config_path):
#    with FirewallRuleSet(sample_config_path) as rule_set:
#        assert len(rule_set._rules) == 4
#        rule_set.save()
#
#
# @patch(
#    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
#    return_value="OPNsense Test",
# )
# @patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
# def test_rule_set_write_rules_back(mocked_version_utils: MagicMock, sample_config_path):
#    test_etree: Element = ElementTree.fromstring(TEST_XML)
#    e2 = list(list(test_etree)[0])[0]
#    with FirewallRuleSet(sample_config_path) as rule_set:
#        e1 = rule_set._rules[0].to_etree()
#        e1s = (
#            ElementTree.tostring(e1, xml_declaration=False, encoding="utf8")
#            .decode()
#            .replace("\n", "")
#        )
#        e2s = re.sub(
#            r">(\s*)<",
#            "><",
#            ElementTree.tostring(e2, xml_declaration=False, encoding="utf8")
#            .decode()
#            .replace("\n", ""),
#        )
#        assert elements_equal(e1, e2), f"Firewall rules not same:\n" f"{e1s}\n" f"{e2s}\n"
#        rule_set.save()
#
