# Copyright: (c) 2023, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
This module provides utilities for interactions with the OPNsense config file located at
/conf/config.xml. It includes classes and methods to read, modify, and manage the configuration
specific to different modules and OPNsense versions.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Optional, Dict
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    version_utils,
    opnsense_utils,
    module_index,
)


class OPNSenseConfigUsageError(Exception):
    """
    Exception raised for errors related to improper usage of the OPNSense module.
    """



class MissingConfigDefinitionForModuleError(Exception):
    """
    Exception raised when a required config definition is missing for a module in the
    plugins.module_utils.module_index.VERSION_MAP. Required configs must include
    'php_requirements' and 'configure_functions'.
    """



class ModuleMisconfigurationError(Exception):
    """
    Exception raised when module configurations are not in the expected format as defined in the
    plugins.module_utils.module_index.VERSION_MAP.
    """



class UnsupportedOPNsenseVersion(Exception):
    """
    Exception raised when an OPNsense version is not supported by the collection.
    """



class UnsupportedVersionForModule(Exception):
    """
    Exception raised when no configuration map could be found for a given module and version.
    """



class UnsupportedModuleSettingError(Exception):
    """
    Exception raised when an attempt is made to access an invalid or unsupported setting in a Module.
    """

    pass


class OPNsenseModuleConfig:
    """
    A class to handle OPNsense module configuration.

    This class provides methods to load, modify, and save configurations specific to OPNsense modules.
    It also includes functionality to apply settings and manage PHP requirements and configure functions
    based on the OPNsense version and module name.

    Attributes:
        _config_xml_tree (Element): The XML tree of the configuration file.
        _config_path (str): The file path of the configuration.
        _config_map (dict): The mapping of settings and their XPath in the XML tree.
        _module_name (str): The name of the module.
        _opnsense_version (str): The OPNsense version.
    """

    _config_xml_tree: Element
    _config_path: str
    _config_map: dict
    _module_name: str
    _opnsense_version: str

    def __init__(self, module_name: str, path: str = "/conf/config.xml"):
        """
        Initializes the OPNsenseModuleConfig class.

        Args:
            module_name (str): The name of the module.
            path (str, optional): The path to the config.xml file. Defaults to "/conf/config.xml".
        """
        self._module_name = module_name
        self._config_path = path
        self._config_xml_tree = self._load_config()
        self._opnsense_version = version_utils.get_opnsense_version()

        try:
            version_map: dict = module_index.VERSION_MAP[self._opnsense_version]
        except KeyError as ke:
            raise UnsupportedOPNsenseVersion(
                f"OPNsense version '{self._opnsense_version}' not supported by puzzle.opnsense collection"
            ) from ke

        if self._module_name not in version_map:
            raise UnsupportedVersionForModule(
                f"Module '{self._module_name}' not supported "
                f"for OPNsense version '{self._opnsense_version}'."
            )

        self._config_map = version_map[self._module_name]

    def _load_config(self) -> Element:
        """
        Loads the config.xml file and returns its root element.

        Returns:
            Element: The root element of the config.xml file.
        """
        return ElementTree.parse(self._config_path).getroot()

    def __enter__(self) -> "OPNsenseModuleConfig":
        """
        Enters the context manager for the OPNsenseModuleConfig class.

        Returns:
            OPNsenseModuleConfig: The instance of OPNsenseModuleConfig.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exits the context manager for OPNsenseModuleConfig.

        Checks if the configuration has changed and not been saved, raising a RuntimeError if so.

        Args:
            exc_type: The exception type.
            exc_val: The exception value.
            exc_tb: The traceback.

        Raises:
            RuntimeError: If there are unsaved changes in the configuration.
        """
        if exc_type:
            raise exc_type(f"Exception occurred: {exc_val}")
        if self.changed:
            raise RuntimeError("Config has changed. Cannot exit without saving.")

    def save(self) -> bool:
        """
        Saves the config to the file if changes have been made.

        Returns:
        - bool: True if changes were saved, False if no changes were detected.
        """
        if self.changed:
            tree: ElementTree.ElementTree = ElementTree.ElementTree(
                self._config_xml_tree
            )
            tree.write(self._config_path, encoding="utf-8", xml_declaration=True)
            self._config_xml_tree = self._load_config()
            return True
        return False

    @property
    def changed(self) -> bool:
        """Checks if changes have been made to the config."""
        return (
            ElementTree.tostring(self._load_config()).decode()
            != ElementTree.tostring(self._config_xml_tree).decode()
        )

    def get(self, setting_name: str) -> Element:
        """
        Retrieves a specific configuration setting for a setting name.

        Parameters:
        - setting_name (str): The name of the setting to retrieve.

        Returns:
        - Element: The retrieved setting element.
        """
        if setting_name not in self._config_map:
            raise UnsupportedModuleSettingError(
                f"Setting '{setting_name}' is not supported in module '{self._module_name}' "
                f"for OPNsense version '{self._opnsense_version}'"
            )
        return self._config_xml_tree.find(self._config_map[setting_name])

    def _get_php_requirements(self) -> list:
        """
        Retrieves the PHP requirements for a given module from a version map.

        Returns:
        - list: PHP requirements for the module.

        Raises:
        - MissingConfigDefinitionForModuleError: If no PHP requirements
          are defined in the version map for the module.
        - ModuleMisconfigurationError: If PHP requirements are not in list format.
        """

        php_requirements: Optional[list] = self._config_map.get("php_requirements")

        # enforce presence of php_requirements in the VERSION_MAP
        if php_requirements is None:
            raise MissingConfigDefinitionForModuleError(
                f"Module '{self._module_name}' has no php_requirements defined in "
                f"the plugins.module_utils.module_index.VERSION_MAP for given "
                f"OPNsense version '{self._opnsense_version}'."
            )

        # ensure php_requirements are defined as a list
        if not isinstance(php_requirements, list):
            raise ModuleMisconfigurationError(
                f"PHP requirements (php_requirements) for the module '{self._module_name}' are "
                f"not provided as a list in the VERSION_MAP using OPNsense version '{self._opnsense_version}'."
            )

        # return list
        return php_requirements

    def _get_configure_functions(self) -> dict:
        """
        Retrieves configure functions for a module from version-specific mapping.

        This function checks a mapping dictionary for configure functions
        associated with a specified module. It returns a dictionary of these
        functions if available.

        Parameters:
        - module (str): Name of the module to retrieve configure functions for.

        Returns:
        - Optional[dict]: Dictionary of configure functions for the module, or
        None if not found or improperly formatted.

        Raises:
        - MissingConfigDefinitionForModuleError: If no configure functions
        are defined in the map for the module.
        - ModuleMisconfigurationError: If configure functions are not formatted
        as a dictionary.

        Example:
            functions = _get_configure_functions('network')
            # Returns configure functions for the 'network' module

        Note:
            Functionality depends on accurate and complete version_map.
        """

        configure_functions: Optional[dict] = self._config_map.get(
            "configure_functions"
        )

        # enforce presence of configure_functions in the VERSION_MAP
        if configure_functions is None:
            raise MissingConfigDefinitionForModuleError(
                f"Module '{self._module_name}' has no configure_functions defined in "
                f"the plugins.module_utils.module_index.VERSION_MAP for given "
                f"OPNsense version '{self._opnsense_version}'."
            )

        # ensure configure_functions are defined as a list
        if not isinstance(configure_functions, dict):
            raise ModuleMisconfigurationError(
                f"Configure functions (configure_functions) for the module '{self._module_name}' are "
                f"not provided as a list in the VERSION_MAP using OPNsense version '{self._opnsense_version}'."
            )

        # return list
        return configure_functions

    def apply_settings(self) -> List[str]:
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

        # get module specific php_requirements
        php_requirements: list = self._get_php_requirements()

        # get module specific configure_functions
        configure_functions: dict = self._get_configure_functions()

        cmd_output: list = []

        # run configure functions with all required php dependencies and store their output.
        for value in configure_functions.values():
            cmd_output.append(
                opnsense_utils.run_function(
                    php_requirements=php_requirements,
                    configure_function=value["name"],
                    configure_params=value["configure_params"],
                )
            )

        return cmd_output

    def set(self, value: str, setting: str) -> None:
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
        xpath = self._config_map.get(setting)

        # create a copy of the _config_dict
        _setting: Element = self._config_xml_tree.find(xpath)

        if _setting.text in [None, "", " "]:
            raise NotImplementedError("Currently only text settings supported")

        _setting.text = value

    @property
    def diff(self) -> Optional[Dict[str, str]]:
        """
        Compares the in-memory configuration with the configuration on the file path
        and returns a dictionary of differences.

        Returns:
        - Optional[Dict[str, str]]: A dictionary containing the differences between
          the in-memory configuration and the file-based configuration.

        Example:
        - diff might return {'setting1': 'new_value', 'setting2': 'changed_value'}.
        """
        file_config_tree = ElementTree.parse(self._config_path)
        file_config = file_config_tree.getroot()

        # Create a dictionary to store the differences
        config_diff = {}

        for setting_name, xpath in self._config_map.items():
            if setting_name in ["php_requirements", "configure_functions"]:
                continue

            # Find the setting in the file-based configuration
            file_setting = file_config.find(xpath)

            # Find the setting in the in-memory configuration
            in_memory_setting = self._config_xml_tree.find(xpath)

            # Compare the values
            if in_memory_setting.text != file_setting.text:
                config_diff[setting_name] = in_memory_setting.text

        return config_diff
