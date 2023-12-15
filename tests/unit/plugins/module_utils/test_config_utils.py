# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the plugins.module_utils.config_utils module."""

# This is probably intentional and required for the fixture
# pylint: disable=redefined-outer-name

from __future__ import absolute_import, division, print_function

__metaclass__val = type


import os
from tempfile import NamedTemporaryFile
from typing import List, Dict
from unittest.mock import patch, MagicMock
from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    UnsupportedOPNsenseVersion,
    UnsupportedModuleSettingError,
    ModuleMisconfigurationError,
    MissingConfigDefinitionForModuleError,
    UnsupportedVersionForModule,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "test_module": {
            "hostname": "system/hostname",
            "php_requirements": ["req_1", "req_2"],
            "configure_functions": {
                "test_configure_function": {
                    "name": "test_configure_function",
                    "configure_params": ["param_1"],
                },
            },
        },
        "missing_php_requirements": {
            "setting_1": "settings/one",
            "setting_2": "settings/two",
            # No php_requirements
            "configure_functions": {},
        },
        "missing_configure_functions": {
            "setting_1": "settings/one",
            "setting_2": "settings/two",
            # No configure_functions
            "php_requirements": [],
        },
        "invalid_php_requirements": {
            "setting_1": "settings/one",
            "setting_2": "settings/two",
            # No php_requirements and configure_functions
            "php_requirements": "must be a list instead of a string",
            "configure_functions": {
                "test_configure_function": {
                    "name": "test_configure_function",
                    "configure_params": ["param_1"],
                },
            },
        },
        "invalid_configure_functions": {
            "setting_1": "settings/one",
            "setting_2": "settings/two",
            # No php_requirements and configure_functions
            "php_requirements": ["req_1", "req_2"],
            "configure_functions": ["must", "be", "a", "dict"],
        },
    },
}

<<<<<<< HEAD
# Test XML configuration content
TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
        <system>
            <hostname>test_name</hostname>
        </system>
    </opnsense>
=======

@pytest.fixture(scope="module")
def sample_config_path():
    """
    Example xml config
    """
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
def opnsense_config(_: MagicMock, sample_config_path):
    """
    Returns an OPNsense config object
    :param mock_object:
    :param sample_config_path:
    :return: OPNsenseConfig: The OPNsenseConfig object
    """
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
def test_set_item(_: MagicMock, opnsense_config, sample_config_path):
    """
    Test setting a value in the config.

    Given a sample OPNsense configuration file, the test verifies that a new key-value pair
    can be added to the config using the OPNsenseConfig object.

    The expected behavior is that the added key-value pair is present in the config
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
>>>>>>> 4eec021 (fixup! pylint fixes)
    """


<<<<<<< HEAD
@pytest.fixture(scope="function")
def sample_config_path(request):
=======
    with OPNsenseConfig(version_map=VERSION_MAP, path=sample_config_path) as new_config:
        assert "new_key" in new_config
        assert new_config["new_key"] == "new_value"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_del_item(_: MagicMock, opnsense_config, sample_config_path):
>>>>>>> 4eec021 (fixup! pylint fixes)
    """
    Fixture that creates a temporary file with a test XML configuration.
    The file  is used in the tests.

    Returns:
    - str: The path to the temporary file.
    """
<<<<<<< HEAD
    with patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
        return_value="OPNsense Test",
    ), patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP",
        TEST_VERSION_MAP,
=======

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
def test_save(_: MagicMock, sample_config_path):
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

    The expected behavior is that the `changed` property is False initially,
    and True after making changes to the config.
    """

    assert not opnsense_config.changed
    opnsense_config["test_key"] = "modified_value"
    assert opnsense_config.changed
    opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_exit_without_saving(_: MagicMock, sample_config_path):
    """
    Test exiting the context without saving changes.

    Given a sample OPNsense configuration file, the test verifies that when changes are made
    to the config using the OPNsenseConfig object, attempting to exit the context without
    saving the changes raises a RuntimeError.

    The expected behavior is that a RuntimeError is raised with the message "Config has changed.
    Cannot exit without saving."
    """
    with pytest.raises(
        RuntimeError, match="Config has changed. Cannot exit without saving."
>>>>>>> 4eec021 (fixup! pylint fixes)
    ):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

<<<<<<< HEAD
    # Cleanup after the fixture is used
    os.unlink(temp_file.name)
=======

def test_get_nested_item(opnsense_config):
    """
    Test retrieving a nested value from the config.

    Given a sample OPNsense configuration file, the test verifies that a specific nested key-value
    pair can be retrieved using the OPNsenseConfig object.

    The expected behavior is that the retrieved value matches the original value
    in the config file.
    """

    assert opnsense_config["test_nested_key_1"]["test_nested_key_2"] == "test_value"
    assert not opnsense_config.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_set_nested_item(_: MagicMock, opnsense_config, sample_config_path):
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
def test_del_nested_item(_: MagicMock, opnsense_config, sample_config_path):
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
    _: MagicMock, opnsense_config, sample_config_path
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
    _: MagicMock, opnsense_config, sample_config_path
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
    "ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils.OPNsenseConfig._get_configure_functions"  # pylint: disable=line-too-long
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils.OPNsenseConfig._get_php_requirements"  # pylint: disable=line-too-long
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense 23.1",
)
def test_apply_module_setting(
    _: MagicMock,
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
    ]

    test_configure_functions = {
        "system_timezone_configure": {
            "name": "system_timezone_configure",
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
            configure_function="plugins_configure",
            configure_params=["'dns'", "true"],
        ),
    ]
    run_function_mock_object.assert_has_calls(expected_calls, any_order=True)
    assert len(result) == len(test_configure_functions)
>>>>>>> 4eec021 (fixup! pylint fixes)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense X.X.X",
)
<<<<<<< HEAD
def test_unsupported_opnsense_version(
    mocked_version_util: MagicMock, sample_config_path
=======
def test_version_not_found_in_version_map(
    _: MagicMock, opnsense_config, sample_config_path # pylint: disable=unused-argument
>>>>>>> 4eec021 (fixup! pylint fixes)
):
    """
    Test case to verify that an UnsupportedOPNsenseVersion exception is raised
    when attempting to initialize OPNsenseModuleConfig with an unsupported OPNsense version.

    Args:
    - mocked_version_util (MagicMock): A mock for version_utils.get_opnsense_version.
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with pytest.raises(
        UnsupportedOPNsenseVersion,
        match="OPNsense version 'OPNsense X.X.X' not supported by puzzle.opnsense collection",
    ):
        _val = OPNsenseModuleConfig(module_name="test_module", path=sample_config_path)


def test_unsupported_module(sample_config_path):
    """
    Test case to verify that an UnsupportedVersionForModule exception is raised
    when attempting to initialize OPNsenseModuleConfig with an unsupported module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with pytest.raises(
        UnsupportedVersionForModule,
        match=r"Module 'unsupported_module' not supported "
        "for OPNsense version 'OPNsense Test'.",
    ):
        _val = OPNsenseModuleConfig(
            module_name="unsupported_module", path=sample_config_path
        )


def test_unsupported_module_setting(sample_config_path):
    """
    Test case to verify that an UnsupportedModuleSettingError exception is raised
    when attempting to retrieve an unsupported module setting.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        with pytest.raises(
            UnsupportedModuleSettingError,
            match="Setting 'unsupported' is not supported in module 'test_module' "
            "for OPNsense version 'OPNsense Test'",
        ):
            _val = new_config.get("unsupported")


def test_php_requirements_must_be_present(sample_config_path):
    """
    Test case to verify that a MissingConfigDefinitionForModuleError exception is raised
    when attempting to retrieve PHP requirements that are missing for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="missing_php_requirements", path=sample_config_path
    ) as new_config:
        with pytest.raises(
            MissingConfigDefinitionForModuleError,
            match=r"Module 'missing_php_requirements' has no php_requirements defined in "
            "the plugins.module_utils.module_index.VERSION_MAP for given "
            "OPNsense version 'OPNsense Test'.",
        ):
            _val = new_config._get_php_requirements()


def test_config_functions_must_be_present(sample_config_path):
    """
    Test case to verify that a MissingConfigDefinitionForModuleError exception is raised
    when attempting to retrieve configure functions that are missing for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="missing_configure_functions", path=sample_config_path
    ) as new_config:
        with pytest.raises(
            MissingConfigDefinitionForModuleError,
            match=r"Module 'missing_configure_functions' has no configure_functions defined in "
            "the plugins.module_utils.module_index.VERSION_MAP for given "
            "OPNsense version 'OPNsense Test'.",
        ):
            _val = new_config._get_configure_functions()


def test_php_requirements_must_be_list(sample_config_path):
    """
    Test case to verify that a ModuleMisconfigurationError exception is raised
    when PHP requirements are not provided as a list.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="invalid_php_requirements", path=sample_config_path
    ) as new_config:
        with pytest.raises(
            ModuleMisconfigurationError,
            match=r"PHP requirements \(php_requirements\) for the module 'invalid_php_requirements' are "
            "not provided as a list in the VERSION_MAP using OPNsense version 'OPNsense Test'.",
        ):
            _val = new_config._get_php_requirements()


def test_configure_functions_must_be_dict(sample_config_path):
    """
    Test case to verify that a ModuleMisconfigurationError exception is raised
    when configure functions are not provided as a dictionary.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="invalid_configure_functions", path=sample_config_path
    ) as new_config:
        with pytest.raises(
            ModuleMisconfigurationError,
            match=r"Configure functions \(configure_functions\) for the module 'invalid_configure_functions' are "
            "not provided as a list in the VERSION_MAP using OPNsense version 'OPNsense Test'.",
        ):
            _val = new_config._get_configure_functions()


def test_get_php_requirements(sample_config_path):
    """
    Test case to verify the correct retrieval of PHP requirements for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module", path=sample_config_path
    ) as new_config:

        requirements: List[str] = new_config._get_php_requirements()

        assert (
            requirements
            == TEST_VERSION_MAP["OPNsense Test"]["test_module"]["php_requirements"]
        )


def test_get_configure_functions(sample_config_path):
    """
    Test case to verify the correct retrieval of configure functions for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module", path=sample_config_path
    ) as new_config:

        requirements: Dict = new_config._get_configure_functions()

        assert (
            requirements
            == TEST_VERSION_MAP["OPNsense Test"]["test_module"]["configure_functions"]
        )


def test_changed(sample_config_path):
    """
    Test case to verify that the `changed` property correctly identifies changes
    in the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        new_config.set(value="testtest", setting="hostname")
        assert new_config.changed
        new_config.save()


def test_get_setting(sample_config_path):
    """
    Test case to verify the correct retrieval of a specific setting from the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        hostname_setting: Element = new_config.get("hostname")
        assert isinstance(hostname_setting, Element)
        assert "test_name" == hostname_setting.text
        new_config.save()


def test_save_on_changed(sample_config_path):
    """
    Test case to verify that the configuration is saved when changes are made.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        new_config.set(value="testtest", setting="hostname")
        assert new_config.save()


def test_save_on_not_changed(sample_config_path):
    """
    Test case to verify that the configuration is not saved when no changes are made.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        assert not new_config.save()


def test_diff_on_change(sample_config_path):
    """
    Test case to verify that the `diff` property correctly identifies changes
    in the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        new_config.set(value="testtest", setting="hostname")
        diff = new_config.diff

        assert diff == {"hostname": "testtest"}
        new_config.save()


def test_diff_on_no_change(sample_config_path):
    """
    Test case to verify that the `diff` property correctly identifies no changes
    in the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig("test_module", path=sample_config_path) as new_config:
        diff = new_config.diff
        assert diff == {}
