# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for interactions with the OPNsense config file /conf/config.xml"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from typing import Any
from xml.etree import ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils, version_utils


class OPNsenseConfig:
    """
    Utility context manager for interactions with the OPNsense config file /conf/config.xml.

    Usage:
       with OPNsenseConfig() as config:
           # Access configuration values
           value = config["key"]

           # Modify configuration values
           config["key"] = new_value

           # Delete configuration values
           del config["key"]

           # Save changes
           config.save()

    Note:
       - The context manager ensures that any changes made to the config are saved before exiting the block.
    """

    VERSION_MAP = {
        "OPNsense 22.7 (amd64/OpenSSL)": {
            "system_settings":{
                "hostname": "system/hostname",
                "domain": "system/domain",
                # Add other mappings here.
            }
        },
        "OPNsense 23.1": {
            "system_settings":{
                "hostname": 'system/hostname',
                "domain": "system/domain",
                # Add other mappings here.
            },
            "test":"test1"
        },
        # Add other versions and their mappings here.
    }

    _config_path: str
    _config_dict: dict

    def __init__(self, path: str = "/conf/config.xml"):
        """
        Initializes an instance of OPNsenseConfig.

        :param path:  The path to the OPNsense config file (default: "/conf/config.xml").
        """
        self._config_path = path
        self._config_dict = self._parse_config_from_file()
        self.version = version_utils.get_opnsense_version()

    def __enter__(self) -> "OPNsenseConfig":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exits the context manager and checks if the config has changed and not saved.
        :raises RuntimeError: If changes are present which have not been saved.
        :return:
        """
        if exc_type:
            raise exc_type(f"Exception occurred: {exc_val}")
        if self.changed:
            raise RuntimeError("Config has changed. Cannot exit without saving.")

    def __getitem__(self, key: Any) -> Any:
        return self._config_dict[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._config_dict[key] = value

    def __delitem__(self, key: Any) -> None:
        del self._config_dict[key]

    def __contains__(self, key: Any) -> bool:
        return key in self._config_dict

    def _parse_config_from_file(self) -> dict:
        _config_root: ElementTree = ElementTree.parse(self._config_path).getroot()
        return xml_utils.etree_to_dict(_config_root)["opnsense"] or {}

    def save(self) -> bool:
        """
        Saves the config dictionary to the config file if changes have been made.

        :return: True if changes were saved, False if no changes were detected.
        """
        if self.changed:
            new_config_root = xml_utils.dict_to_etree("opnsense", self._config_dict)[0]
            new_tree = ElementTree.ElementTree(new_config_root)
            new_tree.write(self._config_path, encoding='utf-8', xml_declaration=True)
            self._config_dict = self._parse_config_from_file()
            return True
        return False

    @property
    def changed(self) -> bool:
        """
        Enters the context manager.

        :return: True if changes have been made to the config, False otherwise.
        """
        orig_dict = self._parse_config_from_file()
        return orig_dict != self._config_dict


    def _get_xpath(self, module: str = None, setting: str = None, map_dict = None):

        map_dict = self.VERSION_MAP.get(self.version)

        if module in map_dict:
            if setting in map_dict[module]:
                return map_dict[module][setting]

        #for key, value in map_dict.items():
        #    if isinstance(value, dict):
        #        result = self.get_by_xpath(value)
        #        if result is not None:
        #            return result


    def set_module_setting(self, value: str, module: str = None, setting: str = None):
        """
        utility to set config specific setting
        """

        # get xpath from key_mapping
        xpath = self._get_xpath(module = module, setting = setting)

        # create a copy of the _config_dict
        #_config_dict = self._config_dict

        # iterate over xpath value to get specific key
        for key in xpath.split("/"):
            self._config_dict = self._config_dict[key]

        print(self._config_dict)

        self._config_dict = value


    def get_module_setting(self, module: str = None, setting: str = None) -> str:
        """
        utility to get config specific setting
        """

        # get xpath from key_mapping
        xpath = self._get_xpath(module = module, setting = setting)

        # create a copy of the _config_dict
        _config_dict = self._config_dict

        # iterate over xpath value to get specific key
        for key in xpath.split("/"):
            _config_dict = _config_dict[key]

        # return key
        return _config_dict
