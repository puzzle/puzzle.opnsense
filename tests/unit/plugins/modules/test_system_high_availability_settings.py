# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the ansible_collections.puzzle.opnsense.plugins.modules.test_system_high_availability_settings"""  # pylint: disable=line-too-long

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
import os

from ansible_collections.puzzle.opnsense.plugins.modules.system_high_availability_settings import (
    check_hasync_node,
    synchronize_states,
    disable_preempt,
    disconnect_dialup_interfaces,
    synchronize_interface,
    synchronize_peer_ip,
    remote_system_synchronization,
    services_to_synchronize,
    validate_ipv4,
    validate_ip,
    sync_compatibility,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    UnsupportedVersionForModule,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils import (
    OPNSenseGetInterfacesError,
)

import pytest


TEST_VERSION_MAP = {
    "24.1": {
        "system_high_availability_settings": {
            # Add other mappings here
            "hasync": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "disable_preempt": "hasync/disablepreempt",
            "disconnect_dialup_interfaces": "hasync/disconnectppps",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/plugins.inc",
            ],
        },
    },
    "24.7": {
        "system_high_availability_settings": {
            # Add other mappings here
            "hasync": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "disable_preempt": "hasync/disablepreempt",
            "disconnect_dialup_interfaces": "hasync/disconnectppps",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "sync_compatibility": "hasync/pfsyncversion",
            "remote_system_password": "hasync/password",
            "sync_services": "hasync/syncitems",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/plugins.inc",
            ],
        },
    },
}


XML_CONFIG_EMPTY: str = """<?xml version="1.0"?>
    <opnsense>
    </opnsense>
    """

XML_CONFIG_241: str = """<?xml version="1.0"?>
    <opnsense>
      <hasync>
        <pfsyncinterface>lan</pfsyncinterface>
        <synchronizetoip/>
        <username/>
        <password/>
      </hasync>
    </opnsense>
    """

XML_CONFIG_247: str = """<?xml version="1.0"?>
    <opnsense>
      <hasync version="1.0.0">
        <disablepreempt>0</disablepreempt>
        <disconnectppps>0</disconnectppps>
        <pfsyncenabled>0</pfsyncenabled>
        <pfsyncinterface>lan</pfsyncinterface>
        <pfsyncpeerip/>
        <pfsyncversion>1400</pfsyncversion>
        <synchronizetoip/>
        <username/>
        <password/>
        <syncitems/>
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
        return_value="24.7",
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
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.modules.system_high_availability_settings.opnsense_utils.run_command",  # pylint: disable=line-too-long
    return_value={"stdout": "opt2:vagrant,lan:LAN", "stderr": None},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_EMPTY], indirect=True)
def test_check_hasync_node(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    assert sample_config.get("hasync") is None
    check_hasync_node(sample_config)
    assert sample_config.get("hasync") is not None
    assert sample_config.get("synchronize_interface").text == "lan"

    assert sample_config.get("synchronize_config_to_ip") is not None
    assert sample_config.get("synchronize_config_to_ip").text is None

    assert sample_config.get("remote_system_username") is not None
    assert sample_config.get("remote_system_username").text is None

    assert sample_config.get("remote_system_password") is not None
    assert sample_config.get("remote_system_password").text is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_states_241(mocked_version_utils: MagicMock, sample_config):
    synchronize_states(sample_config, True)
    assert sample_config.get("synchronize_states").text == "on"
    synchronize_states(sample_config, False)
    assert sample_config.get("synchronize_states") is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_states_247(mocked_version_utils: MagicMock, sample_config):
    for i in range(2):
        synchronize_states(sample_config, True)
        assert sample_config.get("synchronize_states").text == "1"
    for i in range(2):
        synchronize_states(sample_config, False)
        assert sample_config.get("synchronize_states").text == "0"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_disable_preempt_241(mocked_version_utils: MagicMock, sample_config):
    disable_preempt(sample_config, True)
    assert sample_config.get("disable_preempt").text == "on"
    disable_preempt(sample_config, False)
    assert sample_config.get("disable_preempt") is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_disable_preempt_247(mocked_version_utils: MagicMock, sample_config):
    disable_preempt(sample_config, True)
    assert sample_config.get("disable_preempt").text == "1"
    disable_preempt(sample_config, False)
    assert sample_config.get("disable_preempt").text == "0"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_disconnect_dialup_interfaces_241(
    mocked_version_utils: MagicMock, sample_config
):
    disconnect_dialup_interfaces(sample_config, True)
    assert sample_config.get("disconnect_dialup_interfaces").text == "on"
    disconnect_dialup_interfaces(sample_config, False)
    assert sample_config.get("disconnect_dialup_interfaces") is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_disconnect_dialup_interfaces_247(
    mocked_version_utils: MagicMock, sample_config
):
    disconnect_dialup_interfaces(sample_config, True)
    assert sample_config.get("disconnect_dialup_interfaces").text == "1"
    disconnect_dialup_interfaces(sample_config, False)
    assert sample_config.get("disconnect_dialup_interfaces").text == "0"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={"stdout": "opt2:vagrant,lan:LAN", "stderr": None},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_interface(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    synchronize_interface(sample_config, "vagrant")
    assert sample_config.get("synchronize_interface").text == "opt2"
    synchronize_interface(sample_config, "LAN")
    assert sample_config.get("synchronize_interface").text == "lan"
    with pytest.raises(ValueError) as excinfo:
        synchronize_interface(sample_config, "wan")
    assert (
        str(excinfo.value)
        == "'wan' is not a valid interface. If the interface exists, ensure it is enabled and also not virtual."
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={"stdout": "", "stderr": None},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_interface_failure(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    with pytest.raises(OPNSenseGetInterfacesError) as excinfo:
        synchronize_interface(sample_config, "LAN")
    assert "error encountered while getting interfaces, no interfaces available" in str(
        excinfo.value
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={"stdout": "", "stderr": "there was an error"},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_interface_success(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    with pytest.raises(OPNSenseGetInterfacesError) as excinfo:
        synchronize_interface(sample_config, "LAN")
    assert "error encountered while getting interfaces" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_peer_ip_241(mocked_version_utils: MagicMock, sample_config):
    synchronize_peer_ip(sample_config, "240.0.0.240")
    assert sample_config.get("synchronize_peer_ip").text == "240.0.0.240"
    synchronize_peer_ip(sample_config, None)
    assert sample_config.get("synchronize_peer_ip") is None
    with pytest.raises(ValueError) as excinfo:
        synchronize_peer_ip(sample_config, "test")
    assert (
        str(excinfo.value)
        == "Setting synchronize_peer_ip has to be a valid IPv4 address"
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_synchronize_peer_ip_247(mocked_version_utils: MagicMock, sample_config):
    synchronize_peer_ip(sample_config, "240.0.0.240")
    assert sample_config.get("synchronize_peer_ip").text == "240.0.0.240"
    synchronize_peer_ip(sample_config, "fe80::e7fe:b025:807f:b41e")
    assert sample_config.get("synchronize_peer_ip").text == "fe80::e7fe:b025:807f:b41e"
    synchronize_peer_ip(sample_config, None)
    assert sample_config.get("synchronize_peer_ip") is not None
    assert sample_config.get("synchronize_peer_ip").text is None
    with pytest.raises(ValueError) as excinfo:
        synchronize_peer_ip(sample_config, "test")
    assert (
        str(excinfo.value) == "Setting synchronize_peer_ip has to be a valid IP address"
    )


def test_validate_ipv4():
    assert validate_ipv4("240.0.0.240")
    assert not validate_ipv4("test")
    assert not validate_ipv4("510.2440.-1.3")
    assert not validate_ipv4("240.0.0.240.1")
    assert not validate_ipv4("240.0.0.")
    assert not validate_ipv4("240.0.0")
    assert not validate_ipv4("2a02:150:a60d::2df:94:1:510")


def test_validate_ip():
    assert validate_ip("240.0.0.240")
    assert validate_ip("2a02:150:a60d::2df:94:1:510")
    assert validate_ip("::1")
    assert validate_ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    assert not validate_ip("test")
    assert not validate_ip("510.2440.-1.3")
    assert not validate_ip("240.0.0.240.1")
    assert not validate_ip("240.0.0.")
    assert not validate_ip("240.0.0")


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_remote_system_synchronization(mocked_version_utils: MagicMock, sample_config):
    remote_system_synchronization(sample_config, "127.0.0.1", "test", "vagrant")
    assert sample_config.get("synchronize_config_to_ip").text == "127.0.0.1"
    assert sample_config.get("remote_system_username").text == "test"
    assert sample_config.get("remote_system_password").text == "vagrant"

    remote_system_synchronization(sample_config, None, None, None)
    assert sample_config.get("synchronize_config_to_ip").text == "127.0.0.1"
    assert sample_config.get("remote_system_username").text == "test"
    assert sample_config.get("remote_system_password").text == "vagrant"

    remote_system_synchronization(sample_config, None, "test", "vagrant")
    assert sample_config.get("synchronize_config_to_ip") is not None
    assert sample_config.get("synchronize_config_to_ip").text is None
    assert sample_config.get("remote_system_username").text == "test"
    assert sample_config.get("remote_system_password").text == "vagrant"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={
        "stdout_lines": [
            "aliases,Aliases",
            "authservers,Auth Servers",
            "captiveportal,Captive Portal",
            "certs,Certificates",
            "ssh,OpenSSH",
        ],
        "stderr": "",
    },
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_services_to_synchronize_241(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    for i in range(2):
        services = ["Aliases", "Auth Servers", "Captive Portal", "Certificates", "ssh"]
        services_to_synchronize(sample_config, services)
        assert sample_config.get("hasync").find("synchronizealiases").text == "on"
        assert sample_config.get("hasync").find("synchronizessh").text == "on"
        assert sample_config.get("hasync").find("synchronizecron") is None

    services_to_synchronize(sample_config, "Certificates")
    assert sample_config.get("hasync").find("synchronizecron") is None
    assert sample_config.get("hasync").find("synchronizealiases") is None
    assert sample_config.get("hasync").find("synchronizecerts").text == "on"
    with pytest.raises(ValueError) as excinfo:
        services_to_synchronize(sample_config, "bababooey")
    assert (
        str(excinfo.value)
        == "Service bababooey could not be found in your OPNsense installation."
        + " These are all the available services: Aliases, Auth Servers, Captive Portal, Certificates, OpenSSH."
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={
        "stdout_lines": [
            "aliases,Aliases",
            "authservers,Auth Servers",
            "captiveportal,Captive Portal",
            "certs,Certificates",
            "ssh,OpenSSH",
        ],
        "stderr": "",
    },
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_247], indirect=True)
def test_services_to_synchronize_247(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    for i in range(2):
        services = ["Aliases", "Auth Servers", "Captive Portal", "Certificates", "ssh"]
        services_to_synchronize(sample_config, services)
        installed_services = sample_config.get("sync_services").text.split(",")
        assert "aliases" in installed_services
        assert "ssh" in installed_services
        assert "cron" not in installed_services

    services_to_synchronize(sample_config, "Certificates")
    installed_services = sample_config.get("sync_services").text.split(",")
    assert "aliases" not in installed_services
    assert "cron" not in installed_services
    assert "certs" in installed_services
    with pytest.raises(ValueError) as excinfo:
        services_to_synchronize(sample_config, "bababooey")
    assert (
        str(excinfo.value)
        == "Service bababooey could not be found in your OPNsense installation."
        + " These are all the available services: Aliases, Auth Servers, Captive Portal, Certificates, OpenSSH."
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command",
    return_value={
        "stdout_lines": [],
        "stderr": "there was an error",
    },
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_services_to_synchronize_failure(
    mocked_version_utils: MagicMock, mocked_command_out: MagicMock, sample_config
):
    with pytest.raises(OPNSenseGetInterfacesError) as excinfo:
        services_to_synchronize(sample_config, "cron")
    assert str(excinfo.value) == "error encountered while getting services"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.7",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_sync_compatibility(mocked_version_utils: MagicMock, sample_config):
    sync_compatibility(sample_config, "<24.7")
    assert sample_config.get("sync_compatibility").text == "1301"
    sync_compatibility(sample_config, ">24.7")
    assert sample_config.get("sync_compatibility").text == "1400"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="24.1",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
@pytest.mark.parametrize("sample_config", [XML_CONFIG_241], indirect=True)
def test_sync_compatibility_unsupported_version(
    mocked_version_utils: MagicMock, sample_config
):
    with pytest.raises(UnsupportedVersionForModule) as excinfo:
        sync_compatibility(sample_config, "<24.7")
    assert (
        str(excinfo.value)
        == "Setting sync_compatibility is only supported for opnsense versions 24.7 and above"
    )
