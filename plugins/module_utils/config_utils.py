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
    xml_utils,
)


class OPNSenseConfigUsageError(Exception):
    """
    Exception raised for errors related to improper usage of the OPNSense module.
    """


class MissingConfigDefinitionForModuleError(Exception):
    """
    Exception raised when a required config definition is missing for a module in the
    ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP.
    Required configs must include 'php_requirements' and 'configure_functions'.
    """


class ModuleMisconfigurationError(Exception):
    """
    Exception raised when module configurations are not in the expected format as defined in the
    ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP.
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
    Exception raised when an attempt is made to access an invalid or
    unsupported setting in a Module.
    """


class OPNsenseModuleConfig:
    """
    A class to handle OPNsense module configuration.

    This class provides methods to load, modify, and save configurations specific
    to OPNsense modules. It also includes functionality to apply settings and manage
    PHP requirements and configure functions based on the OPNsense version and module name.

    Attributes:
        opnsense_version (str): The OPNsense version.
        _config_xml_tree (Element): The XML tree of the configuration file.
        _config_path (str): The file path of the configuration.
        _config_maps (List[str]): The mappings of settings and their XPath in the XML tree.
        _config_contexts (dict): List of required config_contexts
        _module_name (str): The name of the module.
        _check_mode (bool): If the module is run in check_mode or not
    """

    opnsense_version: str
    _config_xml_tree: Element
    _config_path: str
    _module_name: str
    _config_maps: Dict[str, dict] = {}
    _config_contexts: List[str]
    _check_mode: bool

    def __init__(
        self,
        module_name: str,
        config_context_names: List[str],
        path: str = "/conf/config.xml",
        check_mode: bool = False,
    ):
        """
        Initializes the OPNsenseModuleConfig class.

        Args:
            module_name (str): The name of the module.
            check_mode (bool): Check mode
            config_context_names (List[str]): Names of required config contexts.
            path (str, optional): The path to the config.xml file. Defaults to "/conf/config.xml".
        """
        self._module_name = module_name
        self._config_contexts = config_context_names
        self._config_path = path
        self._config_xml_tree = self._load_config()
        self.opnsense_version = version_utils.get_opnsense_version()
        self._check_mode = check_mode
        try:
            version_map: dict = module_index.VERSION_MAP[self.opnsense_version]
        except KeyError as ke:
            raise UnsupportedOPNsenseVersion(
                f"OPNsense version '{self.opnsense_version}' not supported "
                "by puzzle.opnsense collection.\n"
                f"Supported versions are {list(module_index.VERSION_MAP.keys())}"
            ) from ke
        for config_context_name in config_context_names:
            if config_context_name not in version_map:
                raise UnsupportedVersionForModule(
                    f"Config context '{config_context_name}' not supported "
                    f"for OPNsense version '{self.opnsense_version}'.\n"
                    f"Supported config contexts are {list(version_map.keys())}"
                )

            self._config_maps[config_context_name] = version_map[config_context_name]

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
            # module.fail_json will always yield a SystemExit exception
            # we need to raise this exception "as is" to avoid ansible warnings
            # If however an unexpected exception was risen which was not a result of
            # module.fail_json raising this warning is ok, and we need the exceptions
            # details to troubleshoot the issue
            if isinstance(exc_val, SystemExit):
                raise
            raise exc_type(f"Exception occurred: {exc_val}")
        if self.changed and not self._check_mode:
            raise RuntimeError("Config has changed. Cannot exit without saving.")

    def save(self, override_changed: bool = False) -> bool:
        """
        Saves the config to the file if changes have been made.

        Returns:
        - bool: True if changes were saved, False if no changes were detected.
        """

        if not self.changed and not override_changed:
            return False
        tree: ElementTree.ElementTree = ElementTree.ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)
        self._config_xml_tree = self._load_config()
        return True

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
        for cfg_map in self._config_maps.values():
            if setting_name in cfg_map:
                return self._config_xml_tree.find(cfg_map[setting_name])

        supported_settings: List[str] = []
        for cfg_map in self._config_maps.values():
            supported_settings.extend(cfg_map.keys())

        if "php_requirements" in supported_settings:
            supported_settings.remove("php_requirements")
        if "configure_functions" in supported_settings:
            supported_settings.remove("configure_functions")

        raise UnsupportedModuleSettingError(
            f"Setting '{setting_name}' is not supported in module '{self._module_name}' "
            f"for OPNsense version '{self.opnsense_version}'."
            f"Supported settings are {supported_settings}"
        )

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

        all_php_requirements: list = []

        for cfg_map in self._config_maps.values():
            php_requirements: Optional[list] = cfg_map.get("php_requirements")

            # enforce presence of php_requirements in the VERSION_MAP
            if php_requirements is None:
                raise MissingConfigDefinitionForModuleError(
                    f"Module '{self._module_name}' has no php_requirements defined in "
                    f"the ansible_collections.puzzle.opnsense.plugins.module_utils.module_index.VERSION_MAP for given "  # pylint: disable=line-too-long
                    f"OPNsense version '{self.opnsense_version}'."
                )

            # ensure php_requirements are defined as a list
            if not isinstance(php_requirements, list):
                raise ModuleMisconfigurationError(
                    f"PHP requirements (php_requirements) for the module '{self._module_name}' are "
                    "not provided as a list in the VERSION_MAP using OPNsense version"
                    f"'{self.opnsense_version}'."
                )

            all_php_requirements.extend(php_requirements)

        return all_php_requirements

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

        all_configure_functions: dict = {}

        for cfg_map in self._config_maps.values():
            configure_functions: Optional[dict] = cfg_map.get("configure_functions")

            # enforce presence of configure_functions in the VERSION_MAP
            if configure_functions is None:
                raise MissingConfigDefinitionForModuleError(
                    f"Module '{self._module_name}' has no configure_functions defined in "
                    "the ansible_collections.puzzle.opnsense.plugins.module_utils."
                    "module_index.VERSION_MAP for given OPNsense version "
                    f"'{self.opnsense_version}'."
                )

            # ensure configure_functions are defined as a list
            if not isinstance(configure_functions, dict):
                raise ModuleMisconfigurationError(
                    "Configure functions (configure_functions) for the module "
                    f"'{self._module_name}' are "
                    "not provided as a list in the VERSION_MAP using OPNsense version "
                    f"'{self.opnsense_version}'."
                )

            all_configure_functions.update(configure_functions)

        return all_configure_functions

    def apply_settings(self) -> List[dict]:
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
            meta_dict = {"function": value["name"], "params": value["configure_params"]}
            if not self._check_mode:
                result_dict = opnsense_utils.run_function(
                    php_requirements=php_requirements,
                    configure_function=value["name"],
                    configure_params=value["configure_params"],
                )
            else:
                result_dict = {
                    "check_mode": "Ansible running in check mode, does not execute configure functions",  # pylint: disable=line-too-long
                    "rc": 0,
                }
            cmd_output.append({**meta_dict, **result_dict})

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
        xpath: Optional[str] = None
        for cfg_map in self._config_maps.values():
            if setting in cfg_map:
                xpath = cfg_map.get(setting)

        if xpath is None:
            raise ModuleMisconfigurationError(
                f"Could not access given setting {setting}"
            )
        # create a copy of the _config_dict
        _setting: Element = self._config_xml_tree.find(xpath)

        # there are conditions where a config option is not present in
        # the XML unless it's configured. In that case _settings will be
        # None at this point. If it is, we will have to create the new
        # element first to be able to set it's .text value.
        if _setting is None:
            # get parent of new element
            _setting_parent: Element = self._config_xml_tree.find(
                "/".join(xpath.split("/")[:-1])
            )

            # create new empty element
            element: Element = xml_utils.dict_to_etree(xpath.split("/")[-1], {})

            # append the new element to it's parent
            _setting_parent.extend(element)

            # rediscover the element
            _setting: Element = self._config_xml_tree.find(xpath)

        # If the element is present we will verify it's .text value
        elif _setting.text is None or _setting.text.strip() == "":
            # check if setting has children
            if list(_setting):
                raise AttributeError(
                    f"Cannot assign value to node '{_setting}' with child elements."
                )

        _setting.text = value

    @property
    def diff(self) -> [Dict[dict, dict]]:
        """
        Compares the in-memory configuration with the configuration on the file path
        and returns a dictionary of differences.

        Returns:
        - Dict[dict, dict]: A dictionary containing the before and
          after values (the in-memory configuration and the file-based configuration).

        Example:
        - diff might return {'before': {"foo": "bar"}, 'after': {"foo": "baz"}}.
        """
        file_config_tree = ElementTree.parse(self._config_path)
        file_config = file_config_tree.getroot()

        # Create a dictionary to store the differences
        config_diff_before = {}
        config_diff_after = {}
        for cfg_map in self._config_maps.values():
            for setting_name, xpath in cfg_map.items():
                if setting_name in ["php_requirements", "configure_functions"]:
                    continue

                # Find the setting in the file-based configuration
                file_config_element = file_config.find(xpath)

                # there are conditions where a config option is not present in
                # the XML unless it's configured. In that case file_config_element will be
                # None at this point. If it is, we will set it's current value to an empty string
                if file_config_element is None:
                    config_diff_before.update({xpath: ""})
                else:
                    config_diff_before.update({xpath: file_config_element.text})

                # Find the setting in the in-memory configuration
                in_memory_element = self._config_xml_tree.find(xpath)

                # there are conditions where a config option is not present in
                # the XML unless it's configured. In that case in_memory_element will be
                # None at this point. If it is, we will set it's current value to an empty string
                if in_memory_element is None:
                    config_diff_after.update({xpath: ""})
                else:
                    config_diff_after.update({xpath: in_memory_element.text})

        return {"before": config_diff_before, "after": config_diff_after}
