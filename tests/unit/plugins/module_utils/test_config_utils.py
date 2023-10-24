# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the plugins.module_utils.config_utils module."""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import os
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import OPNsenseConfig


@pytest.fixture(scope="module")
def sample_config_path():
    # Create a temporary file with sample config for testing
    config_content = """<?xml version="1.0"?>
<opnsense>
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


def test_get_item(sample_config_path):
    """
    Test retrieving a value from the config.

    Given a sample OPNsense configuration file, the test verifies that a specific key-value pair
    can be retrieved using the OPNsenseConfig object.

    The expected behavior is that the retrieved value matches the original value in the config file.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        assert config["test_key"] == "test_value"
        assert not config.save()


def test_set_item(sample_config_path):
    """
    Test setting a value in the config.

    Given a sample OPNsense configuration file, the test verifies that a new key-value pair
    can be added to the config using the OPNsenseConfig object.

    The expected behavior is that the added key-value pair is present in the config
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        config["new_key"] = "new_value"
        assert config["new_key"] == "new_value"
        assert config.save()

    with OPNsenseConfig(path=sample_config_path) as new_config:
        assert "new_key" in new_config
        assert new_config["new_key"] == "new_value"


def test_del_item(sample_config_path):
    """
    Test deleting a value from the config.

    Given a sample OPNsense configuration file, the test verifies that a key-value pair
    can be removed from the config using the `del` statement with the OPNsenseConfig object.

    The expected behavior is that the deleted key is no longer present in the config,
    the `changed` property is True indicating that the config has changed,
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        del config["test_key"]
        assert "test_key" not in config
        assert config.changed
        assert config.save()

    with OPNsenseConfig(path=sample_config_path) as new_config:
        assert "test_key" not in new_config


def test_contains(sample_config_path):
    """
    Test checking if a key exists in the config.

    Given a sample OPNsense configuration file, the test verifies that the existence of a key
    in the config can be checked using the `in` statement with the OPNsenseConfig object.

    The expected behavior is that the test_key is found in the config,
    and a non-existent key is not found.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        assert "test_key" in config
        assert "nonexistent_key" not in config
        assert not config.save()


def test_save(sample_config_path):
    """
    Test saving changes to the config.

    Given a sample OPNsense configuration file, the test verifies that changes made to the config
    using the OPNsenseConfig object can be saved.

    The expected behavior is that the `save` method returns True when the config has changed,
    indicating that the changes were successfully saved.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        config["test_key"] = "modified_value"
        config["test_nested_key_1"]["test_nested_key_2"] = "modified_nested_value"
        assert config.save()
    # Reload the saved config and assert the changes were saved
    reloaded_config = xml_utils.etree_to_dict(ElementTree.parse(sample_config_path).getroot())["opnsense"]
    assert reloaded_config["test_key"] == "modified_value"
    assert reloaded_config["test_nested_key_1"]["test_nested_key_2"] == "modified_nested_value"

    with OPNsenseConfig(path=sample_config_path) as new_config:
        assert new_config["test_key"] == "modified_value"
        assert new_config["test_nested_key_1"]["test_nested_key_2"] == "modified_nested_value"


def test_changed(sample_config_path):
    """
    Test checking if the config has changed.

    Given a sample OPNsense configuration file, the test verifies that the `changed` property
    of the OPNsenseConfig object correctly indicates whether the config has changed.

    The expected behavior is that the `changed` property is False initially, and True after making changes
    to the config.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        assert not config.changed
        config["test_key"] = "modified_value"
        assert config.changed
        config.save()


def test_exit_without_saving(sample_config_path):
    """
    Test exiting the context without saving changes.

    Given a sample OPNsense configuration file, the test verifies that when changes are made to the config
    using the OPNsenseConfig object, attempting to exit the context without saving the changes raises a RuntimeError.

    The expected behavior is that a RuntimeError is raised with the message "Config has changed. Cannot exit without saving."
    """
    with pytest.raises(RuntimeError, match="Config has changed. Cannot exit without saving."):
        with OPNsenseConfig(path=sample_config_path) as config:
            config["test_key"] = "modified_value"
            # The RuntimeError should be raised upon exiting the context without saving


def test_get_nested_item(sample_config_path):
    """
    Test retrieving a nested value from the config.

    Given a sample OPNsense configuration file, the test verifies that a specific nested key-value
    pair can be retrieved using the OPNsenseConfig object.

    The expected behavior is that the retrieved value matches the original value in the config file.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        assert config["test_nested_key_1"]["test_nested_key_2"] == "test_value"
        assert not config.save()


def test_set_nested_item(sample_config_path):
    """
    Test setting a nested value in the config.

    Given a sample OPNsense configuration file, the test verifies that a new nested key-value pair
    can be added to the config using the OPNsenseConfig object.

    The expected behavior is that the added key-value pair is present in the config
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        config["new_key"]["new_nested_key"] = "new_value"
        assert config["new_key"]["new_nested_key"] == "new_value"
        assert config.save()

    with OPNsenseConfig(path=sample_config_path) as new_config:
        assert "new_key" in new_config
        assert new_config["new_key"]["new_nested_key"] == "new_value"


def test_del_nested_item(sample_config_path):
    """
    Test deleting a nested value from the config.

    Given a sample OPNsense configuration file, the test verifies that a nested key-value pair
    can be removed from the config using the `del` statement with the OPNsenseConfig object.

    The expected behavior is that the deleted key is no longer present in the config,
    the `changed` property is True indicating that the config has changed,
    and the `save` method returns True indicating that the config has changed. When using
    a new config context the changes are expected to persist.
    """
    with OPNsenseConfig(path=sample_config_path) as config:
        del config["test_nested_key_1"]["test_nested_key_2"]
        assert "test_nested_key_2" not in config["test_nested_key_1"]
        assert config.changed
        assert config.save()

    with OPNsenseConfig(path=sample_config_path) as new_config:
        assert "test_nested_key_2" not in new_config
