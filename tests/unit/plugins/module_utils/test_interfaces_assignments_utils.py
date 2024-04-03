#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: skip-file
import os
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element


import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_assignments_utils import (
    InterfaceAssignment,
    InterfacesSet,
    OPNSenseInterfaceNotFoundError,
    OPNSenseDeviceNotFoundError,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "interfaces_assignments": {
            "interfaces": "interfaces",
            "php_requirements": [],
            "configure_functions": {},
        }
    }
}

TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
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
        </interfaces>
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


def test_simple_interface_assignment_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    test_etree_interface_assignment: Element = list(list(test_etree_opnsense)[0])[2]
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment.from_xml(
        test_etree_interface_assignment
    )
    assert test_interface_assignment.identifier == "opt1"
    assert test_interface_assignment.device == "em3"
    assert test_interface_assignment.descr == "DMZ"


def test_wan_interface_assignment_to_etree():
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment(
        identifier="wan",
        device="em2",
        descr="WAN",
        ipaddr="dhcp",
        dhcphostname=None,
        mtu=None,
        subnet=None,
        gateway=None,
        media=None,
        mediaopt=None,
        blockbogons=1,
        blockpriv=1,
        ipaddrv6="dhcp6",
        lock=1,
    )
    setattr(test_interface_assignment, "dhcp6-ia-pd-len", "0")

    test_element = test_interface_assignment.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_assignment: Element = list(list(orig_etree)[0])[0]

    assert xml_utils.elements_equal(test_element, orig_test_interface_assignment)


def test_lan_interface_assignment_to_etree():
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment(
        identifier="lan",
        device="em1",
        enable=1,
        descr="LAN",
        ipaddr="192.168.56.10",
        spoofmac=None,
        subnet="21",
        blockbogons=1,
        ipaddrv6="track6",
        lock=1,
    )
    setattr(test_interface_assignment, "track6-interface", "wan")
    setattr(test_interface_assignment, "track6-prefix-id", "0")

    test_element = test_interface_assignment.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_assignment: Element = list(list(orig_etree)[0])[1]

    assert xml_utils.elements_equal(test_element, orig_test_interface_assignment)


def test_opt1_interface_assignment_to_etree():
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment(
        identifier="opt1", device="em3", descr="DMZ", spoofmac=None, lock=1
    )
    test_element = test_interface_assignment.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_assignment: Element = list(list(orig_etree)[0])[2]

    assert xml_utils.elements_equal(test_element, orig_test_interface_assignment)


def test_opt2_interface_assignment_to_etree():
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment(
        identifier="opt2",
        device="em0",
        descr="VAGRANT",
        enable=1,
        spoofmac=None,
        lock=1,
        ipaddr="dhcp",
        dhcphostname=None,
        dhcprejectfrom=None,
        adv_dhcp_pt_timeout=None,
        adv_dhcp_pt_retry=None,
        adv_dhcp_pt_select_timeout=None,
        adv_dhcp_pt_reboot=None,
        adv_dhcp_pt_backoff_cutoff=None,
        adv_dhcp_pt_initial_interval=None,
        adv_dhcp_pt_values="SavedCfg",
        adv_dhcp_send_options=None,
        adv_dhcp_request_options=None,
        adv_dhcp_required_options=None,
        adv_dhcp_option_modifiers=None,
        adv_dhcp_config_advanced=None,
        adv_dhcp_config_file_override=None,
        adv_dhcp_config_file_override_path=None,
    )

    setattr(test_interface_assignment, "alias-address", None)
    setattr(test_interface_assignment, "alias-subnet", "32")

    test_element = test_interface_assignment.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_assignment: Element = list(list(orig_etree)[0])[3]

    assert xml_utils.elements_equal(test_element, orig_test_interface_assignment)


def test_lo0_interface_assignment_to_etree():
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment(
        internal_dynamic="1",
        identifier="lo0",
        device="lo0",
        descr="Loopback",
        enable=1,
        ipaddr="127.0.0.1",
        ipaddrv6="::1",
        subnet="8",
        subnetv6="128",
        type="none",
        virtual="1",
    )

    test_element = test_interface_assignment.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_assignment: Element = list(list(orig_etree)[0])[4]

    assert xml_utils.elements_equal(test_element, orig_test_interface_assignment)


def test_simple_interface_assignment_from_ansible_module_params_simple(sample_config_path):
    test_params: dict = {
        "identifier": "wan",
        "device": "vtnet1",
        "description": "lan_interface",
    }
    test_interface_assignment: InterfaceAssignment = InterfaceAssignment.from_ansible_module_params(
        test_params
    )
    assert test_interface_assignment.identifier == "wan"
    assert test_interface_assignment.device == "vtnet1"
    assert test_interface_assignment.descr == "lan_interface"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_assignment_from_ansible_module_params_with_description_update(
    mock_get_version, sample_config_path
):
    test_params: dict = {
        "identifier": "lan",
        "device": "em1",
        "description": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        test_interface_assignment: InterfaceAssignment = (
            InterfaceAssignment.from_ansible_module_params(test_params)
        )
        interfaces_set.update(test_interface_assignment)
        assert interfaces_set.changed
        interfaces_set.save()

    with InterfacesSet(sample_config_path) as new_interfaces_set:
        new_test_interface_assignment = new_interfaces_set.find(identifier="lan")
        assert new_test_interface_assignment.identifier == "lan"
        assert new_test_interface_assignment.device == "em1"
        assert new_test_interface_assignment.descr == "test_interface"
        new_interfaces_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_assignment_from_ansible_module_params_with_device_update(
    mock_get_version, sample_config_path
):
    test_params: dict = {
        "identifier": "wan",
        "device": "em0",
        "description": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        test_interface_assignment: InterfaceAssignment = (
            InterfaceAssignment.from_ansible_module_params(test_params)
        )
        interfaces_set.update(test_interface_assignment)
        assert interfaces_set.changed
        interfaces_set.save()

    with InterfacesSet(sample_config_path) as new_interfaces_set:
        new_test_interface_assignment = new_interfaces_set.find(identifier="wan")
        assert new_test_interface_assignment.identifier == "wan"
        assert new_test_interface_assignment.device == "em0"
        assert new_test_interface_assignment.descr == "test_interface"
        new_interfaces_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_assignment_from_ansible_module_params_with_not_existing_device(
    mock_get_version, sample_config_path
):
    test_params: dict = {
        "identifier": "wan",
        "device": "test",
        "description": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseDeviceNotFoundError) as excinfo:
            test_interface_assignment: InterfaceAssignment = (
                InterfaceAssignment.from_ansible_module_params(test_params)
            )
            interfaces_set.update(test_interface_assignment)
            interfaces_set.save()
        assert "Device was not found on OpnSense Instance!" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_assignment_from_ansible_module_params_with_not_existing_interface(
    mock_get_version, sample_config_path
):
    test_params: dict = {
        "identifier": "test",
        "device": "em0",
        "description": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseInterfaceNotFoundError) as excinfo:
            test_interface_assignment: InterfaceAssignment = (
                InterfaceAssignment.from_ansible_module_params(test_params)
            )
            interfaces_set.update(test_interface_assignment)
            interfaces_set.save()
        assert "Interface not found for update error:" in str(excinfo.value)
