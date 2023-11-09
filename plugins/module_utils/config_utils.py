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

    _config_path: str
    _config_dict: dict

    def __init__(self, version_map: dict = None, path: str = "/conf/config.xml"):
        """
        Initializes an instance of OPNsenseConfig.

        :param path:  The path to the OPNsense config file (default: "/conf/config.xml").
        :param version_map:  The version_map of the specific module.
        """
        self._config_path = path
        self._config_dict = self._parse_config_from_file()
        self.version_map = version_map

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

    def _search_map(self, dictionary, key):
        """
        Recursively search for a key in a nested dictionary.

        This function traverses through a nested dictionary structure to find the value associated with the
        specified key. It searches through all levels of nested dictionaries until it finds the key or
        exhausts all possibilities.

        Parameters:
        - dictionary (dict): The dictionary to search through. This can be a multi-level nested dictionary.
        - key (str): The key to search for in the dictionary.

        Returns:
        - The value associated with the found key, or None if the key is not found in the dictionary.

        Example:
        - Given the dictionary `{"interfaces": {"wan": {"if": 'interfaces/wan/if'}}}` and the key `'if'`,
        the function will return `'interfaces/wan/if'`.
        """

        if isinstance(dictionary, dict):
            for k, v in dictionary.items():
                if k == key:
                    return v
                else:
                    result = self._search_map(v, key)
                    if result is not None:
                        return result

    def _get_xpath(self, module: str = None, setting: str = None, map_dict=None):
        """
        Retrieve the XPath for a given module and setting from the version-specific mapping.

        This method takes a module and setting as input and looks up their corresponding XPath
        in a version-specific mapping dictionary. It performs a direct lookup if the setting is
        top-level within the module or initiates a recursive search if the setting is nested.

        Parameters:
        - module (str, optional): The name of the module to look up. Defaults to None.
        - setting (str, optional): The name of the setting within the module to look up. Defaults to None.
        - map_dict (dict, optional): A pre-fetched version map dictionary. If not provided,
        it will use the version_map attribute based on the instance's version attribute. Defaults to None.

        Returns:
        - str or None: The XPath as a string if the module and setting are found within the map. If the
        module or setting cannot be found, or the inputs are None, it returns None.

        Example:
        - For an instance with version 'OPNsense 23.1', if version_map['OPNsense 23.1'] contains {'system': {'hostname': 'system/hostname'}},
        and we call _get_xpath(module='system', setting='hostname'), it will return 'system/hostname'.
        """

        map_dict = self.version_map.get(self.version)

        if map_dict is None:
            raise KeyError(f"{self.version} was not not found in version_map")

        # Check if the provided module is in the map
        if module in map_dict:
            # If the setting is directly within the module, return it
            if setting in map_dict[module]:
                return map_dict[module][setting]
            # If the setting is nested, search recursively
            else:
                return self._search_map(map_dict[module], setting)

        return None

    def _get_php_requirements(self, module: str = None, setting: str = None) -> list:
        """
        Retrive list of php_requirements for a given module and setting from the version-specific mapping.
        """

        map_dict = self.version_map.get(self.version)

        if map_dict is None:
            raise KeyError(f"{self.version} was not not found in version_map")

        # Check if the provided module is in the map
        if module in map_dict:
            # If the setting is directly within the module, return it
            if setting in map_dict[module]:
                return map_dict[module][setting]
            # If the setting is nested, search recursively
            else:
                return self._search_map(map_dict[module], setting)

        return None

    def _get_configure_functions(self, module: str = None, setting: str = None) -> dict:
        """
        Retrive list of configure_functions for a given module and setting from the version-specific mapping.
        """

        map_dict = self.version_map.get(self.version)

        if map_dict is None:
            raise KeyError(f"{self.version} was not not found in version_map")

        # Check if the provided module is in the map
        if module in map_dict and setting in map_dict[module]:
            # Check if the setting contains a dictionary of configure functions
            if isinstance(map_dict[module][setting], dict):
                return map_dict[module][setting]

    def set_module_setting(self, value: str, module: str = None, setting: str = None):
        """
        utility to set config specific setting
        """

        # get xpath from key_mapping
        xpath = self._get_xpath(module=module, setting=setting)

        # create a copy of the _config_dict
        _config_dict = self._config_dict.copy()

        # iterate over xpath value to get specific key
        keys = xpath.split("/")

        for key in keys[:-1]:
            _config_dict = _config_dict.setdefault(key, {})

        # Update the final value
        _config_dict[keys[-1]] = value

    def del_module_setting(self, module: str = None, setting: str = None):
        """
        utility to delete config specific setting
        """

        # get xpath from key_mapping
        xpath = self._get_xpath(module=module, setting=setting)

        # create a copy of the _config_dict
        _config_dict = self._config_dict.copy()

        # iterate over xpath value to get specific key
        keys = xpath.split("/")

        for key in keys[:-1]:
            _config_dict = _config_dict.setdefault(key, {})

        # Update the final value
        _config_dict[keys[-1]] = None

    def get_module_setting(self, module: str = None, setting: str = None) -> str:
        """
        utility to get config specific setting
        """

        # get xpath from key_mapping
        xpath = self._get_xpath(module=module, setting=setting)

        # create a copy of the _config_dict
        _config_dict = self._config_dict.copy()

        # iterate over xpath value to get specific key
        for key in xpath.split("/"):
            _config_dict = _config_dict[key]

        # return key
        return _config_dict

    #def apply_module_setting(self, module: str = None) -> List[str]:
    #    """
    #    utility to get and apply config specific php_requirements
    #    """
#
    #    # get version and module specific php_requirements
    #    php_requirements = self._get_php_requirements(module=module, setting="php_requirements")
#
    #    # get version and module specific configure_functions
    #    configure_functions = self._get_configure_functions(
    #        module=module,
    #        setting="configure_functions"
    #    )
#
    #    cmd_output = []
#
    #    for key, value in configure_functions.items():
    #        cmd_output.append(opnsense_utils.run_function(
    #            php_requirements=php_requirements,
    #            configure_function=value['name'],
    #            configure_params=value['configure_params'],
    #        )
    #        )
#
    #    return cmd_output
#