# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for interactions with the OPNsense config file /conf/config.xml"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, List, Optional, Union
from xml.etree import ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    version_utils,
    opnsense_utils,
)


class OPNSenseConfigUsageError(Exception):
    """
    Error Class to be raised in improper module usage
    """


class OPNsenseConfig:
    """
    A utility class for managing and interacting with the OPNsense configuration file
    (/conf/config.xml). It provides methods for retrieving, modifying, and applying settings
    specific to different modules based on version-specific requirements.

    The class facilitates operations such as fetching PHP requirements, retrieving and setting
    configuration values, and handling version-specific configurations. It uses a context manager
    to ensure safe handling of the configuration file, allowing changes to be made within a managed
    context.

    Usage:
       with OPNsenseConfig(version_map) as config:
           # Retrieve a configuration value
           value = config.get_module_setting('module', 'setting')

           # Modify a configuration value
           config.set_module_setting('value', 'module', 'setting')

           # Delete a configuration value
           config.del_module_setting('module', 'setting')

           # Apply module-specific settings
           outputs = config.apply_module_setting('module')

           # Save changes to the configuration file
           config.save()

    Note:
       - The context manager ensures that any changes made to the configuration are saved
         before exiting the block. It also provides error handling to ensure that changes
         are not lost.

    Parameters:
    - version_map (dict): A dictionary mapping module versions to their respective settings.
    - path (str, optional): The file path to the OPNsense configuration file. Defaults to
      "/conf/config.xml".

    Methods like _get_php_requirements, _get_configure_functions, etc., offer more granular
    control for advanced operations. They are primarily used internally but can be used
    externally for custom configurations.

    This class raises OPNSenseConfigUsageError for version compatibility issues or other
    configuration-related errors.
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
            new_tree.write(self._config_path, encoding="utf-8", xml_declaration=True)
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

    def _get_module_version_map(self, module: str) -> dict:
        """
        Retrieves the version-specific mapping for a specified module.

        This function accesses the `version_map` attribute to fetch the mapping for the current
        version. If the mapping for the specified version exists, it returns the mapping;
        otherwise, it raises an OPNSenseConfigUsageError.

        Parameters:
        - module (str): The name of the module for which the version-specific mapping is required.

        Returns:
        - dict: A dictionary containing the version-specific mapping for the given module.

        Raises:
        - OPNSenseConfigUsageError: If the current version is not supported for the given module,
          indicated by the absence of the version key in the `version_map`.

        Example:
        - Calling _get_module_version_map('network') for an instance with version '1.0' might
          return the mapping for the 'network' module if version '1.0' is present in `version_map`.

        Note:
        - This function is critical for ensuring that the configuration aligns with the specific
          version requirements of a module.
        """

        if self.version_map.get(self.version):
            return self.version_map.get(self.version)

        else:
            raise OPNSenseConfigUsageError(
                f"Version {self.version} not supported in module {module}"
            )

    def _search_map(self, dictionary, key) -> Optional[str]:
        """
        Recursively search for a key in a nested dictionary.

        This function traverses through a nested dictionary structure to find the value associated
        with the specified key. It searches through all levels of nested dictionaries until it finds
        the key or exhausts all possibilities.

        Parameters:
        - dictionary (dict): The dictionary to search. This can be a multi-level nested dictionary.
        - key (str): The key to search for in the dictionary.

        Returns:
        - The value associated with the found key, or None if the key is not found in the dict.

        Example:
        - Given the dictionary `{"interfaces": {"wan": {"if": 'interfaces/wan/if'}}}`
        and the key `'if'`, the function will return `'interfaces/wan/if'`.
        """

        if isinstance(dictionary, dict):
            for k, v in dictionary.items():
                if k == key:
                    return v
                else:
                    result = self._search_map(v, key)
                    if result is not None:
                        return result

    def _get_xpath(self, module: str, setting: str) -> Union[str, dict]:
        """
        Retrieves the XPath for a given module and setting based on the version-specific mapping.

        This function looks up the XPath in a version-specific mapping dictionary using the provided
        module and setting names. If the setting is directly within the module, it returns it;
        otherwise, it performs a recursive search if the setting is nested within the module.

        Parameters:
        - module (str): The name of the module for which the XPath is sought.
        - setting (str): The specific setting within the module whose XPath is needed.

        Returns:
        - Union[str, dict, None]: The XPath as a string or dict if found, or None if the module
        or setting cannot be found or is not available.

        Raises:
        - OPNSenseConfigUsageError: If the version-specific `version_map` is not set during the
        initialization of the instance.

        Example:
        - Calling _get_xpath('network', 'interface') might return 'network/interface' or a
        dictionary of nested settings if 'interface' is a nested setting within 'network'.

        Note:
        - The function emphasizes the importance of a properly initialized `version_map`.The absence
        of the module in the map or the setting within the module leads to a return value of None.
        """

        if not self.version_map:
            raise OPNSenseConfigUsageError(
                "Module specific version_map was not set during initalization"
            )

        map_dict = self._get_module_version_map(module=module)

        # Check if the provided module is in the map
        if module in map_dict and setting in map_dict[module]:
            # If the setting is directly within the module, return it
            return map_dict[module][setting]
        elif module in map_dict:
            # If the setting is nested, search recursively
            return self._search_map(map_dict[module], setting)

        raise OPNSenseConfigUsageError("Module specific xpath was not found")

    def _get_php_requirements(self, module: str, setting: str) -> list:
        """
        Retrieves a list of PHP requirements for a specific module and setting based on the
        version-specific mapping.

        This function looks up PHP requirements in the version-specific mapping for the given
        module and setting. It returns the list associated with the setting if it's directly
        under the module. If the setting is nested, it performs a recursive search.

        Parameters:
        - module (str): The module's name for which PHP requirements are needed.
        - setting (str): The specific setting within the module.

        Returns:
        - Optional[list]: List of PHP requirements if found, or None if not found or unavailable.

        Example:
        - Calling _get_php_requirements('network', 'extensions') might return a list of required
          PHP extensions for the 'network' module, if 'extensions' is a setting under 'network'.

        Note:
        - The accuracy of the returned requirements depends on the completeness of `version_map`.
          If a module or setting is missing in the map, the function returns None.
        """

        map_dict = self._get_module_version_map(module=module)

        if module in map_dict and setting in map_dict[module]:
            # If the setting is directly within the module, return it
            return map_dict[module][setting]
        elif module in map_dict:
            # If the setting is nested, search recursively
            return self._search_map(map_dict[module], setting)

        raise OPNSenseConfigUsageError("Module specific get_php_requirement were not found")

    def _get_configure_functions(self, module: str, setting: str) -> dict:
        """
        Retrieves configure functions for a specific module and setting from the version-specific
        mapping.

        This function checks the version-specific mapping dictionary for configure functions
        related to a given module and setting. If the setting in the module contains a dictionary
        of configure functions, it is returned.

        Parameters:
        - module (str): Module name for which configure functions are sought.
        - setting (str): Specific setting within the module needing configure functions.

        Returns:
        - Optional[dict]: Dictionary of configure functions if found; None if not found or if
        the setting does not contain a dictionary.

        Example:
        - _get_configure_functions('network', 'routing') might return a dict of functions for
        routing settings in the 'network' module, if present.

        Note:
        - Function's effectiveness depends on the `version_map` being accurate and complete. The
        presence of a module and setting in the map is crucial for function retrieval.
        """

        map_dict = self._get_module_version_map(module=module)

        # Check if the provided module is in the map
        if module in map_dict and setting in map_dict[module]:
            # Check if the setting contains a dictionary of configure functions
            if isinstance(map_dict[module][setting], dict):
                return map_dict[module][setting]

        else:
            raise OPNSenseConfigUsageError("Module specific get_configure_functions were not found")

    def set_module_setting(self, value: str, module: str, setting: str) -> None:
        """
        Sets a specific configuration setting for a given module.

        This function sets a value in the configuration for a specified module and setting. It
        first retrieves the XPath using _get_xpath, then updates the value at the specified
        setting in a copy of the _config_dict.

        Parameters:
        - value (str): The value to set for the specific setting.
        - module (str): The module where the setting resides.
        - setting (str): The specific setting within the module to update.

        Steps:
        - Retrieve XPath for the module and setting.
        - Create a copy of _config_dict.
        - Traverse the XPath, updating nested dictionaries as needed.
        - Set the value at the final key in the XPath.

        Example:
        - Calling set_module_setting('192.168.1.1', 'network', 'gateway') will set the
          'gateway' setting under the 'network' module to '192.168.1.1'.

        Note:
        - This function directly modifies the configuration and should be used with caution.
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

    def del_module_setting(self, module: str, setting: str) -> None:
        """
        Deletes a specific configuration setting for a given module.

        This function deletes a setting in the configuration for a specified module. It retrieves
        the XPath for the setting using _get_xpath, then traverses the XPath in a copy of the
        _config_dict to set the specified setting's value to None.

        Parameters:
        - module (str): The module where the setting resides.
        - setting (str): The specific setting within the module to delete.

        Steps:
        - Retrieve XPath for the module and setting.
        - Create a copy of _config_dict.
        - Traverse the XPath, updating nested dictionaries as needed.
        - Set the value at the final key in the XPath to None.

        Example:
        - Calling del_module_setting('network', 'gateway') will delete the 'gateway' setting
          under the 'network' module.

        Note:
        - This function directly modifies the configuration, effectively deleting the setting.
          Use with caution.
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

    def get_module_setting(self, module: str, setting: str) -> str:
        """
        Retrieves a specific configuration setting for a given module.

        This function fetches a setting from the configuration for a specified module. It first
        obtains the XPath for the setting using _get_xpath, and then traverses this path in a copy
        of the _config_dict to find the desired setting's value.

        Parameters:
        - module (str): The module where the setting resides.
        - setting (str): The specific setting within the module to retrieve.

        Steps:
        - Retrieve XPath for the module and setting.
        - Create a copy of _config_dict.
        - Traverse the XPath to find the specific key.
        - Return the value associated with the key.

        Example:
        - Calling get_module_setting('network', 'gateway') will return the value of the 'gateway'
          setting under the 'network' module.

        Note:
        - This function navigates through configuration, returning the value of the specified
          setting. Ensure the setting path exists to avoid key errors.
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

    def apply_module_setting(self, module: str) -> List[str]:
        """
        Retrieves and applies configuration-specific PHP requirements and configure functions for
        a given module.

        This function first fetches the PHP requirements and configure functions specific to the
        version and module. It then applies these configurations, generating a list of command
        outputs from the application of each configure function.

        Parameters:
        - module (str): The name of the module for which configurations are applied.

        Returns:
        - List[str]: A list of strings representing the output of each applied configuration
          function.

        Steps:
        - Retrieve PHP requirements and configure functions for the module.
        - Apply each configure function with the corresponding PHP requirements.
        - Collect and return the output from each function application.

        Example:
        - Calling apply_module_setting('network') might apply network-specific PHP requirements
          and configure functions, returning their outputs.

        Note:
        - The function relies on properly defined PHP requirements and configure functions for
          each module, as per the version-specific configuration.
        """

        # get version and module specific php_requirements
        php_requirements = self._get_php_requirements(module=module, setting="php_requirements")

        # get version and module specific configure_functions
        configure_functions = self._get_configure_functions(
            module=module, setting="configure_functions"
        )

        cmd_output = []

        for key, value in configure_functions.items():
            cmd_output.append(
                opnsense_utils.run_function(
                    php_requirements=php_requirements,
                    configure_function=value["name"],
                    configure_params=value["configure_params"],
                )
            )

        return cmd_output
