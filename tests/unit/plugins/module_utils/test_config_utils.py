# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the plugins.module_utils.config_utils module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree
from unittest.mock import patch, MagicMock, call

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseConfig,
    OPNSenseConfigUsageError,
)

VERSION_MAP = {
    "OPNsense 22.7 (amd64/OpenSSL)": {
        "system_settings": {
            "hostname": "system/hostname",
            "domain": "system/domain",
            # Add other mappings here.
        }
    },
    "OPNsense 23.1": {
        "system_settings": {
            "hostname": "system/hostname",
            "domain": "system/domain",
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/interfaces.lib.inc",
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/filter.inc",
            ],
            "configure_functions": {
                "system_timezone_configure": {
                    "name": "system_timezone_configure",
                    "configure_params": ["true"],
                },
                "system_trust_configure": {
                    "name": "system_trust_configure",
                    "configure_params": ["true"],
                },
                "system_hostname_configure": {
                    "name": "system_hostname_configure",
                    "configure_params": ["true"],
                },
                "system_resolver_configure": {
                    "name": "system_resolver_configure",
                    "configure_params": ["true"],
                },
                "plugins_configure": {
                    "name": "plugins_configure",
                    "configure_params": ["'dns'", "true"],
                },
                "plugins_configure1": {
                    "name": "plugins_configure",
                    "configure_params": ["'dhcp'", "true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": ["true"],
                },
            },
            # Add other mappings here.
        },
        "test": "test1",
        "interfaces": {
            "wan": {"if": "interfaces/wan/if"},
            # Add other mappings here.
        },
    },
    "OPNsense 1.0.0": {
        "system_settings": {
            "hostname": "system/hostname",
            "domain": "system/domain",
            # Add other mappings here.
        },
    },
}


@pytest.fixture(scope="module")
def sample_config_path():
    # Create a temporary file with sample config for testing
    config_content = """<?xml version="1.0"?>
<opnsense>
    <system>
        <optimization>normal</optimization>
        <hostname>test_name</hostname>
        <domain>test.domain.someplace</domain>
    </system>
    <interfaces>
        <wan>
            <if>vtnet0</if>
        </wan>
    </interfaces>
    <test_key>test_value</test_key>
    <test_nested_key_1>
        <test_nested_key_2>test_value</test_nested_key_2>
    </test_nested_key_1>
    <new_key>
        <new_nested_key></new_nested_key>
    </new_key>
</opnsense>"""
    with NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(config_content.encode())
        temp_file.flush()
        yield temp_file.name
    os.unlink(temp_file.name)


@pytest.fixture(scope="module")
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def opnsense_config(mock_object: MagicMock, sample_config_path):
    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as config:
        return config


def test_get_item(opnsense_config):
    """
    Test retrieving a value from the config.

    Given a sample OPNsense configuration file, the test verifies that a specific key-value pair
    can be retrieved using the OPNsenseConfig object.

    The expected behavior is that the retrieved value matches the original value in the config file.
    """
    assert opnsense_config["test_key"] == "test_value"
    assert not opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_set_item(mock_object: MagicMock, opnsense_config, sample_config_path):
    """
    Test setting a value in the config.

    Given a sample OPNsense configuration file, the test verifies that a new key-value pair
    can be added to the config using the OPNsenseConfig object.

    The expected behavior is that the added key-value pair is present in the config
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """

    opnsense_config["new_key"] = "new_value"
    assert opnsense_config["new_key"] == "new_value"
    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "new_key" in new_config
        assert new_config["new_key"] == "new_value"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_del_item(mock_object: MagicMock, opnsense_config, sample_config_path):
    """
    Test deleting a value from the config.

    Given a sample OPNsense configuration file, the test verifies that a key-value pair
    can be removed from the config using the `del` statement with the OPNsenseConfig object.

    The expected behavior is that the deleted key is no longer present in the config,
    the `changed` property is True indicating that the config has changed,
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """

    del opnsense_config["test_key"]
    assert "test_key" not in opnsense_config
    assert opnsense_config.changed
    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "test_key" not in new_config


def test_contains(opnsense_config):
    """
    Test checking if a key exists in the config.

    Given a sample OPNsense configuration file, the test verifies that the existence of a key
    in the config can be checked using the `in` statement with the OPNsenseConfig object.

    The expected behavior is that the test_key is found in the config,
    and a non-existent key is not found.
    """
    assert "test_key" in opnsense_config
    assert "nonexistent_key" not in opnsense_config
    assert not opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_save(mock_object: MagicMock, sample_config_path):
    """
    Test saving changes to the config.

    Given a sample OPNsense configuration file, the test verifies that changes made to the config
    using the OPNsenseConfig object can be saved.

    The expected behavior is that the `save` method returns True when the config has changed,
    indicating that the changes were successfully saved.
    """

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as config:
        config["test_key"] = "modified_value"
        config["test_nested_key_1"]["test_nested_key_2"] = "modified_nested_value"
        assert config.save()
    # Reload the saved config and assert the changes were saved
    reloaded_config = xml_utils.etree_to_dict(
        ElementTree.parse(sample_config_path).getroot()
    )["opnsense"]
    assert reloaded_config["test_key"] == "modified_value"
    assert (
        reloaded_config["test_nested_key_1"]["test_nested_key_2"]
        == "modified_nested_value"
    )

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert new_config["test_key"] == "modified_value"
        assert (
            new_config["test_nested_key_1"]["test_nested_key_2"]
            == "modified_nested_value"
        )


def test_changed(opnsense_config):
    """
    Test checking if the config has changed.

    Given a sample OPNsense configuration file, the test verifies that the `changed` property
    of the OPNsenseConfig object correctly indicates whether the config has changed.

    The expected behavior is that the `changed` property is False initially, and True after making changes
    to the config.
    """

    assert not opnsense_config.changed
    opnsense_config["test_key"] = "modified_value"
    assert opnsense_config.changed
    opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_exit_without_saving(mock_object: MagicMock, sample_config_path):
    """
    Test exiting the context without saving changes.

    Given a sample OPNsense configuration file, the test verifies that when changes are made to the config
    using the OPNsenseConfig object, attempting to exit the context without saving the changes raises a RuntimeError.

    The expected behavior is that a RuntimeError is raised with the message "Config has changed. Cannot exit without saving."
    """
    with pytest.raises(
        RuntimeError, match="Config has changed. Cannot exit without saving."
    ):
        with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as config:
            config["test_key"] = "modified_value"
            # The RuntimeError should be raised upon exiting the context without saving


def test_get_nested_item(opnsense_config):
    """
    Test retrieving a nested value from the config.

    Given a sample OPNsense configuration file, the test verifies that a specific nested key-value
    pair can be retrieved using the OPNsenseConfig object.

    The expected behavior is that the retrieved value matches the original value in the config file.
    """

    assert opnsense_config["test_nested_key_1"]["test_nested_key_2"] == "test_value"
    assert not opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_set_nested_item(mock_object: MagicMock, opnsense_config, sample_config_path):
    """
    Test setting a nested value in the config.

    Given a sample OPNsense configuration file, the test verifies that a new nested key-value pair
    can be added to the config using the OPNsenseConfig object.

    The expected behavior is that the added key-value pair is present in the config
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """

    opnsense_config["new_key"]["new_nested_key"] = "new_value"
    assert opnsense_config["new_key"]["new_nested_key"] == "new_value"
    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "new_key" in new_config
        assert new_config["new_key"]["new_nested_key"] == "new_value"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_del_nested_item(mock_object: MagicMock, opnsense_config, sample_config_path):
    """
    Test deleting a nested value from the config.

    Given a sample OPNsense configuration file, the test verifies that a nested key-value pair
    can be removed from the config using the `del` statement with the OPNsenseConfig object.

    The expected behavior is that the deleted key is no longer present in the config,
    the `changed` property is True indicating that the config has changed,
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """

    del opnsense_config["test_nested_key_1"]["test_nested_key_2"]
    assert "test_nested_key_2" not in opnsense_config["test_nested_key_1"]
    assert opnsense_config.changed
    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "test_nested_key_2" not in new_config


def test_get_module_setting(opnsense_config):
    """
    Test retrieving module settings from the config.

    Given a sample OPNsense configuration file, the test verifies that specific module settings
    can be retrieved using the `get_module_setting` method of the OPNsenseConfig object.

    The expected behavior is that the retrieved values for given module settings match
    the original values in the config file. Additionally, the `save` method should return False
    indicating that no changes to the config were made during the retrieval process.
    """

    assert (
        opnsense_config.get_module_setting(module="system_settings", setting="hostname")
        == "test_name"
    )
    assert (
        opnsense_config.get_module_setting(module="system_settings", setting="domain")
        == "test.domain.someplace"
    )
    assert (
        opnsense_config.get_module_setting(module="interfaces", setting="if")
        == "vtnet0"
    )
    assert not opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_set_module_setting(
    mock_object: MagicMock, opnsense_config, sample_config_path
):
    """
    Test setting module settings in the config.

    Given a sample OPNsense configuration file, the test verifies that module settings
    can be modified using the `set_module_setting` method of the OPNsenseConfig object.

    The expected behavior is that after setting the module settings, the `save` method returns True
    indicating that the config has changed. When using a new config context, the changes are
    expected to persist and the new values for the given settings should be reflected in the config.
    """

    opnsense_config.set_module_setting(
        module="system_settings", setting="hostname", value="new_test_name"
    )

    opnsense_config.set_module_setting(
        module="system_settings", setting="domain", value="new_test.domain.someplace"
    )

    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "system" in new_config
        assert new_config["system"]["hostname"] == "new_test_name"
        assert new_config["system"]["domain"] == "new_test.domain.someplace"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_del_module_setting(
    mock_object: MagicMock, opnsense_config, sample_config_path
):
    """
    Test deleting module settings from the config.

    Given a sample OPNsense configuration file, the test verifies that module settings
    can be removed using the `del_module_setting` method of the OPNsenseConfig object.

    The expected behavior is that the settings are no longer present in the config
    after deletion. The `changed` property is True, indicating that the config has been modified,
    and the `save` method returns True, confirming that the changes have been saved.
    When using a new config context, the changes should persist and the settings should
    be absent from the config.
    """

    opnsense_config.del_module_setting(module="system_settings", setting="hostname")
    opnsense_config.del_module_setting(module="system_settings", setting="domain")
    assert opnsense_config.save()

    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "system" in new_config
        assert new_config["system"]["hostname"] is None
        assert new_config["system"]["domain"] is None


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils.OPNsenseConfig._get_configure_functions"
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils.OPNsenseConfig._get_php_requirements"
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_apply_module_setting(
    version_mock_object: MagicMock,
    php_mock_object: MagicMock,
    configure_mock_object: MagicMock,
    run_function_mock_object: MagicMock,
    opnsense_config,
):
    """
    Test the application of module settings within the OPNsense configuration.

    This test ensures that given a set of PHP requirements and configure functions,
    the `apply_module_setting` method applies the settings correctly by invoking
    the appropriate functions with the expected parameters.

    The method under test should retrieve the PHP requirements and configuration
    functions for the specified module and execute them, collecting the output.

    We mock the dependencies involved in this process to assert that the functions
    are called as expected, and the resultant output is correctly aggregated.

    The expected behavior is that for each configure function provided, a corresponding
    call to `opnsense_utils.run_function` is made with the appropriate PHP requirements
    and parameters, and the result of these function calls is returned as a list of outputs.
    """

    test_php_requirements = [
        "/usr/local/etc/inc/config.inc",
        "/usr/local/etc/inc/util.inc",
        "/usr/local/etc/inc/system.inc",
        "/usr/local/etc/inc/interfaces.lib.inc",
        "/usr/local/etc/inc/interfaces.inc",
        "/usr/local/etc/inc/filter.inc",
    ]

    test_configure_functions = {
        "system_timezone_configure": {
            "name": "system_timezone_configure",
            "configure_params": ["true"],
        },
        "system_resolver_configure": {
            "name": "system_resolver_configure",
            "configure_params": ["true"],
        },
        "plugins_configure": {
            "name": "plugins_configure",
            "configure_params": ["'dns'", "true"],
        },
    }

    php_mock_object.return_value = test_php_requirements
    configure_mock_object.return_value = test_configure_functions

    # Act: Call the apply_module_setting method
    result = opnsense_config.apply_module_setting(module="system_settings")

    # Assert: Check that run_function was called correctly
    expected_calls = [
        call(
            php_requirements=test_php_requirements,
            configure_function="system_timezone_configure",
            configure_params=["true"],
        ),
        call(
            php_requirements=test_php_requirements,
            configure_function="system_resolver_configure",
            configure_params=["true"],
        ),
        call(
            php_requirements=test_php_requirements,
            configure_function="plugins_configure",
            configure_params=["'dns'", "true"],
        ),
    ]
    run_function_mock_object.assert_has_calls(expected_calls, any_order=True)
    assert len(result) == len(test_configure_functions)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense X.X.X",
)
def test_version_not_found_in_version_map(
    mock_object: MagicMock, opnsense_config, sample_config_path
):
    """
    Test behavior when a non-existent version is accessed in the version map.

    This test patches the `get_opnsense_version` function to return a version string
    that is not present in the version map. The purpose is to verify that the
    `OPNsenseConfig` object raises the appropriate error when attempting to access
    module settings associated with an undefined version.

    The expected behavior is for a KeyError exception to be raised with a message
    indicating that the specified version ("OPNsense X.X.X") was not found in the
    version map. This confirms that the `OPNsenseConfig` object correctly handles
    the situation where a configuration for a given version is requested but doesn't exist.
    """

    with pytest.raises(
        OPNSenseConfigUsageError,
        match="Version OPNsense X.X.X not supported in module system_settings",
    ):
        with OPNsenseConfig(
            version_map=VERSION_MAP, path=sample_config_path
        ) as new_config:
            new_config.get_module_setting(module="system_settings", setting="hostname")
            # The RuntimeError should be raised upon accesing a version that not exists
