# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils module."""

# This is probably intentional and required for the fixture
# pylint: disable=redefined-outer-name,unused-argument,protected-access

from __future__ import absolute_import, division, print_function

import dataclasses

__metaclass__val = type

import os
from tempfile import NamedTemporaryFile
from typing import List, Dict
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    UnsupportedOPNsenseVersion,
    UnsupportedModuleSettingError,
    ModuleMisconfigurationError,
    MissingConfigDefinitionForModuleError,
    UnsupportedVersionForModule,
    ConfigObject,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.enum_utils import ListEnum

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
        "test_module_2": {
            "timezone": "system/timezone",
            "php_requirements": ["req_1", "req_2"],
            "configure_functions": {
                "test_configure_function": {
                    "name": "test_configure_function",
                    "configure_params": ["param_1"],
                },
            },
        },
        "test_module_3": {
            "preserve_logs": "syslog/preservelogs",
            "php_requirements": ["req_1", "req_2"],
            "configure_functions": {
                "test_configure_function": {
                    "name": "test_configure_function",
                    "configure_params": ["param_1"],
                },
            },
        },
        "test_module_4": {
            "hasync_parent": "hasync",
            "remote_system_username": "hasync/username",
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

# Test XML configuration content
TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
        <system>
            <hostname>test_name</hostname>
            <timezone>test_timezone</timezone>
        </system>
        <syslog>
        </syslog>
        <settings>
            <one>1</one>
            <two>2</two>
        </settings>
        <hasync>
            <username />
        </hasync>
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
    ), patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP",
        TEST_VERSION_MAP,
    ):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense X.X.X",
)
def test_unsupported_opnsense_version(
    mocked_version_util: MagicMock, sample_config_path
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
        _val = OPNsenseModuleConfig(
            module_name="test_module",
            config_context_names=["test_module"],
            path=sample_config_path,
            check_mode=False,
        )


def test_unsupported_module(sample_config_path):
    """
    Test case to verify that an UnsupportedVersionForModule exception is raised
    when attempting to initialize OPNsenseModuleConfig with an unsupported module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with pytest.raises(
        UnsupportedVersionForModule,
        match=r"Config context 'unsupported_module' not supported "
        "for OPNsense version 'OPNsense Test'.",
    ):
        _val = OPNsenseModuleConfig(
            module_name="unsupported_module",
            config_context_names=["unsupported_module"],
            path=sample_config_path,
            check_mode=False,
        )


def test_unsupported_module_setting(sample_config_path):
    """
    Test case to verify that an UnsupportedModuleSettingError exception is raised
    when attempting to retrieve an unsupported module setting.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        "test_module", config_context_names=["test_module"], path=sample_config_path
    ) as new_config:
        with pytest.raises(
            UnsupportedModuleSettingError,
            match="Setting 'unsupported' is not supported in module 'test_module' "
            "for OPNsense version 'OPNsense Test'",
        ):
            _val = new_config.get("unsupported")


def test_setting_from_two_contexts_accessible(sample_config_path):
    """
    Test case to verify that a OPNsenseModuleConfig with multiple context can access
    settings of any given context.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        "test_module",
        config_context_names=["test_module", "test_module_2"],
        path=sample_config_path,
    ) as new_config:
        hostname = new_config.get("hostname")
        timezone = new_config.get("timezone")

        assert hostname.text == "test_name"
        assert timezone.text == "test_timezone"


def test_setting_from_another_context_raises_error(sample_config_path):
    """
    Test case to verify that a OPNsenseModuleConfig with multiple context cannot access
    a context it has not been initialized with.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        "test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
    ) as new_config:
        with pytest.raises(
            UnsupportedModuleSettingError,
            match="Setting 'timezone' is not supported in module 'test_module' "
            "for OPNsense version 'OPNsense Test'",
        ):
            _timezone = new_config.get("timezone")


def test_php_requirements_must_be_present(sample_config_path):
    """
    Test case to verify that a MissingConfigDefinitionForModuleError exception is raised
    when attempting to retrieve PHP requirements that are missing for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="missing_php_requirements",
        config_context_names=["missing_php_requirements"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        with pytest.raises(
            MissingConfigDefinitionForModuleError,
            match=r"Module 'missing_php_requirements' has no php_requirements defined in "
            "the ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP for given "  # pylint: disable=line-too-long
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
        module_name="missing_configure_functions",
        config_context_names=["missing_configure_functions"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        with pytest.raises(
            MissingConfigDefinitionForModuleError,
            match=r"Module 'missing_configure_functions' has no configure_functions defined in "
            "the ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP for given "  # pylint: disable=line-too-long
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
        module_name="invalid_php_requirements",
        config_context_names=["invalid_php_requirements"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        with pytest.raises(
            ModuleMisconfigurationError,
            match=(
                r"PHP requirements \(php_requirements\) for the module 'invalid_php_requirements' "
                r"are not provided as a list in the VERSION_MAP using OPNsense version"
                r"'OPNsense Test'."
            ),
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
        module_name="invalid_configure_functions",
        config_context_names=["invalid_configure_functions"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        with pytest.raises(
            ModuleMisconfigurationError,
            match=(
                r"Configure functions \(configure_functions\) for the module "
                r"'invalid_configure_functions' are "
                r"not provided as a list in the VERSION_MAP using OPNsense version "
                r"'OPNsense Test'."
            ),
        ):
            _val = new_config._get_configure_functions()


def test_get_php_requirements(sample_config_path):
    """
    Test case to verify the correct retrieval of PHP requirements for a module.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
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
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
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
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        new_config.set(value="testtest", setting="hostname")
        assert new_config.changed
        new_config.save()


def test_get_setting(sample_config_path):
    """
    Test case to verify the correct retrieval of a specific setting from the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
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
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        new_config.set(value="testtest", setting="hostname")
        assert new_config.save()


def test_save_on_not_changed(sample_config_path):
    """
    Test case to verify that the configuration is not saved when no changes are made.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        assert not new_config.save()


def test_diff_on_change(sample_config_path):
    """
    Test case to verify that the `diff` property correctly identifies changes
    in the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        new_config.set(value="testtest", setting="hostname")
        diff = new_config.diff

        assert diff == {
            "before": {
                "system/hostname": "test_name",
            },
            "after": {
                "system/hostname": "testtest",
            },
        }
        new_config.save()


def test_diff_on_no_change(sample_config_path):
    """
    Test case to verify that the `diff` property correctly identifies no changes
    in the OPNsense configuration.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module",
        config_context_names=["test_module"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        diff = new_config.diff
        assert diff["before"] == diff["after"]


def test_set_with_missing_element(sample_config_path):
    """
    Test case to verify that we can set options for which there is currently element
    in the xml tree. This is the case for example with the preserve_logs setting.
    The xml does not contain the path `syslog/preservelogs` unless the option is configured.
    In this case we expect that the module will create the object.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module_3",
        config_context_names=["test_module_3"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        new_config.set(value="10", setting="preserve_logs")
        diff = new_config.diff

        assert diff == {
            "before": {
                "syslog/preservelogs": "",
            },
            "after": {
                "syslog/preservelogs": "10",
            },
        }
        new_config.save()


def test_fail_set_on_parent_node(sample_config_path):
    """
    Test case to verify that setting a value for a parent node will fail.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module_4",
        config_context_names=["test_module_4"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        with pytest.raises(AttributeError):
            new_config.set("test", "hasync_parent")


def test_success_set_on_empty_leaf_node(sample_config_path):
    """
    Test case to verify that setting a leaf node with a value of None will succeed.

    Args:
    - sample_config_path (str): The path to the temporary test configuration file.
    """
    with OPNsenseModuleConfig(
        module_name="test_module_4",
        config_context_names=["test_module_4"],
        path=sample_config_path,
        check_mode=False,
    ) as new_config:
        new_config.set("test", "remote_system_username")
        assert new_config.get("remote_system_username").text == "test"
        new_config.save()


###
# ConfigObject Tests
###


class TestType(ListEnum):
    __test__ = False
    ONE = "one"
    TWO = "two"


@dataclasses.dataclass
class TestConfigObject(ConfigObject):

    __test__ = False
    name: str
    pretty_name: str
    type: TestType
    _object_root_tag_name: str = "test"

    @classmethod
    def preprocess_ansible_module_params(cls, raw_params: dict) -> dict:
        params: dict = {**raw_params}
        params["pretty_name"] = params["name"].capitalize()
        return params

    @classmethod
    def preprocess_from_xml_data(cls, raw_xml_data: dict) -> dict:
        params: dict = {**raw_xml_data}
        params["pretty_name"] = params["name"].capitalize()
        return params


@dataclasses.dataclass
class TestNestedConfigObject(ConfigObject):

    __test__ = False
    sub_element: TestConfigObject
    _object_root_tag_name: str = "nested"

    @classmethod
    def preprocess_ansible_module_params(cls, raw_params: dict) -> dict:
        return {"sub_element": {"name": raw_params["sub_element_name"]}}


def test_config_object_from_ansible_params_simple() -> None:
    """Basic ConfigObject.from_ansible_module_params test"""
    module_params: dict = {"name": "test_object", "type": "one"}

    test_obj: TestConfigObject = TestConfigObject.from_ansible_module_params(
        module_params
    )

    assert test_obj.name == module_params["name"]
    assert test_obj.type == TestType.ONE


def test_config_object_preprocessed_parameters() -> None:
    """Basic ConfigObject.from_ansible_module_params test"""
    module_params: dict = {"name": "test object", "type": "one"}

    test_obj: TestConfigObject = TestConfigObject.from_ansible_module_params(
        module_params
    )

    assert test_obj.name == module_params["name"]
    assert test_obj.pretty_name == "Test object"
    assert test_obj.type == TestType.ONE


def test_simple_obj_root_tag_name() -> None:
    simple: str = """
        <test>
            <name>test_object</name>
            <type>one</type>
        </test>
    """

    test_element: Element = ET.fromstring(simple)

    test_object: TestConfigObject = TestConfigObject.from_xml_element(test_element)

    assert test_object.name == "test_object"
    assert test_object.pretty_name == "Test_object"
    assert test_object.type == TestType.ONE


def test_simple_obj_extra_data() -> None:
    simple: str = """
        <test>
            <name>test_object</name>
            <extra>Extra Data</extra>
            <type>one</type>
        </test>
    """

    test_element: Element = ET.fromstring(simple)

    test_object: TestConfigObject = TestConfigObject.from_xml_element(test_element)

    assert test_object.name == "test_object"
    assert test_object.pretty_name == "Test_object"
    assert test_object.type == TestType.ONE
    assert test_object.extra_data is not None
    assert "extra" in test_object.extra_data
    assert test_object.extra_data["extra"] == "Extra Data"


def test_simple_obj_extra_data_to_xml() -> None:
    simple_obj: TestConfigObject = TestConfigObject(
        name="test",
        pretty_name="Test Object",
        type=TestType.ONE,
        extra_data={"extra": "Some Data"},
    )

    test_element: Element = simple_obj.to_xml_element()

    assert test_element.tag == "test"
    children: List[Element] = list(test_element)
    assert len(children) == 4
    for child in children:
        assert child.tag in ["name", "pretty_name", "type", "extra"]


def test_nested_obj_extra_data_to_xml() -> None:
    nested_obj: TestNestedConfigObject = TestNestedConfigObject(
        sub_element=TestConfigObject(
            name="test",
            pretty_name="Test Object",
            type=TestType.ONE,
            extra_data={"extra": "Some Data"},
        ),
        extra_data={"extra": "data"},
    )

    expected_element: Element = Element("nested")
    _expected_extra: Element = Element("extra")
    _expected_extra.text = "data"
    _child_obj: Element = Element("sub_element")
    _child_obj_name: Element = Element("name")
    _child_obj_name.text = "test"
    _child_obj_pretty_name: Element = Element("pretty_name")
    _child_obj_pretty_name.text = "Test Object"
    _child_obj_type: Element = Element("type")
    _child_obj_type.text = "one"
    _child_obj_extra: Element = Element("extra")
    _child_obj_extra.text = "Some Data"

    _child_obj.extend(
        [_child_obj_name, _child_obj_pretty_name, _child_obj_type, _child_obj_extra]
    )

    expected_element.extend([_child_obj, _expected_extra])

    actual_element: Element = nested_obj.to_xml_element()

    assert xml_utils.elements_equal(expected_element, actual_element), xml_utils
