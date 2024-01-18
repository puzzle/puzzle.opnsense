#  Copyright: (c) 2023, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
import os
import re
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils.xml_utils import (
    elements_equal,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_rules_utils import (
    FirewallRuleSet,
    FirewallRule,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "firewall_rules": {
            "rules": "filter",
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
        <filter>
            <rule uuid="9c7ecb2c-49f3-4750-bc67-d5b666541999">
                <type>pass</type>
                <interface>wan</interface>
                <ipprotocol>inet</ipprotocol>
                <statetype>keep state</statetype>
                <descr>Allow SSH access</descr>
                <protocol>tcp</protocol>
                <source>
                   <any/>
                </source>
                <destination>
                   <any/>
                   <port>22</port>
                </destination>
            </rule>
            <rule>
                <type>pass</type>
                <interface>wan</interface>
                <ipprotocol>inet</ipprotocol>
                <statetype>keep state</statetype>
                <descr>Allow incoming WebGUI access</descr>
                <protocol>tcp</protocol>
                <source>
                    <any/>
                </source>
                <destination>
                    <any/>
                    <port>443</port>
                </destination>
            </rule>
        </filter>
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
        "plugins.module_utils.version_utils.get_opnsense_version",  # pylint: disable=line-too-long
        return_value="OPNsense Test",
    ), patch.dict(VERSION_MAP, TEST_VERSION_MAP, clear=True):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_load_simple_rules(
    mocked_version_utils: MagicMock, sample_config_path
):
    with FirewallRuleSet(sample_config_path) as rule_set:
        assert len(rule_set._rules) == 2
        rule_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_write_rules_back(mocked_version_utils: MagicMock, sample_config_path):
    test_etree: Element = ElementTree.fromstring(TEST_XML)
    e2 = list(list(test_etree)[0])[0]
    with FirewallRuleSet(sample_config_path) as rule_set:
        e1 = rule_set._rules[0].to_etree()
        e1s = (
            ElementTree.tostring(e1, xml_declaration=False, encoding="utf8")
            .decode()
            .replace("\n", "")
        )
        e2s = re.sub(
            r">(\s*)<",
            "><",
            ElementTree.tostring(e2, xml_declaration=False, encoding="utf8")
            .decode()
            .replace("\n", ""),
        )
        assert elements_equal(e1, e2), (
            f"Firewall rules not same:\n" f"{e1s}\n" f"{e2s}\n"
        )
        rule_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_change_rule_description(
    mocked_version_utils: MagicMock, sample_config_path
):
    with FirewallRuleSet(sample_config_path) as rule_set:
        ssh_rule: FirewallRule = rule_set.find(descr="Allow SSH access")
        ssh_rule.descr = "TEST TEST"

        assert rule_set.changed

        rule_set.save()

    with FirewallRuleSet(sample_config_path) as new_rule_set:
        ssh_rule: FirewallRule = rule_set.find(descr="TEST TEST")

        assert ssh_rule.descr == "TEST TEST"

        new_rule_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_create_new_simple_rule(
    mocked_version_utils: MagicMock, sample_config_path
):
    new_test_rule = FirewallRule(interface="wan", descr="New Test Rule")

    with FirewallRuleSet(sample_config_path) as rule_set:
        rule_set.add_or_update(new_test_rule)

        assert rule_set.changed

        rule_set.save()

    with FirewallRuleSet(sample_config_path) as new_rule_set:
        new_rule: Optional[FirewallRule] = new_rule_set.find(
            interface="wan", descr="New Test Rule"
        )

        assert new_rule is not None
        assert new_rule.interface == "wan"
        assert new_rule.descr == "New Test Rule"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_not_changed_after_save(
    mocked_version_utils: MagicMock, sample_config_path
):
    new_test_rule = FirewallRule(interface="wan", descr="New Test Rule")

    with FirewallRuleSet(sample_config_path) as rule_set:
        rule_set.add_or_update(new_test_rule)

        assert rule_set.changed

        rule_set.save()
        assert not rule_set.changed


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_not_changed_after_duplicate_rule(
    mocked_version_utils: MagicMock, sample_config_path
):
    new_test_rule = FirewallRule(interface="wan", descr="New Test Rule")

    with FirewallRuleSet(sample_config_path) as rule_set:
        rule_set.add_or_update(new_test_rule)

        rule_set.save()

    with FirewallRuleSet(sample_config_path) as same_rule_set:
        same_rule_set.add_or_update(new_test_rule)

        assert not same_rule_set.changed
        same_rule_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_fw_rule_from_ansible_is_same_as_default(
    mocked_version_utils: MagicMock, sample_config_path
):
    mock_ansible_module_params: dict = {
        "action": "pass",
        "category": None,
        "description": "New Test Rule",
        "direction": None,
        "disabled": False,
        "interface": "wan",
        "ipprotocol": "inet",
        "log": False,
        "protocol": None,
        "quick": False,
        "source_invert": None,
        "source_ip": None,
        "source_port": None,
        "state": "present",
        "target_invert": None,
        "target_ip": None,
        "target_port": None,
    }
    ansible_rule: FirewallRule = FirewallRule.from_ansible_module_params(
        mock_ansible_module_params
    )

    new_test_rule = FirewallRule(interface="wan", descr="New Test Rule")

    assert ansible_rule == new_test_rule


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_rule_set_create_new_simple_rule_with_unsupported_action(
    mocked_version_utils: MagicMock, sample_config_path
):
    with pytest.raises(ValueError) as excinfo:
        new_test_rule = FirewallRule(
            interface="wan",
            descr="New Test Rule",
            type="NOT_AVAILBLE_FIREWALLRULEACTION",  # Intentionally invalid type
        )

    assert "NOT_AVAILBLE_FIREWALLRULEACTION" in str(excinfo.value)
