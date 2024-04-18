from dataclasses import field
from typing import List, Dict, Any

from xml.etree.ElementTree import Element, ElementTree, SubElement

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig, UnsupportedModuleSettingError
)


class SystemHighAvailabilitySettings:
    """
    Attributes:
        _general_settings (Dict[str, str | bool])
        _remote_synchronization_settings (dict[str, str])
        _sync_plugins_list (List[str])
        extra_attrs (Dict[str, Any]): Additional attributes for configuration.
    Methods:
        __init__: Initializes with general settings, remote sync settings and plugin sync list.
        from_xml: Creates an instance from XML.
        to_etree: Serializes instance to XML, handling special cases.
        from_ansible_module_params: Creates from Ansible params.
    """

    _general_settings: Dict[str, str | bool]
    _remote_synchronization_settings: dict[str, str]
    _sync_plugins_list: List[str]
    extra_attrs: Dict[str, Any]

    # since only the above attributes are needed, the rest is handled here
    extra_attrs: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __init__(self, _general_settings: Dict[str, str | bool], _remote_synchronization_settings: dict[str, str],
                 _sync_plugins_list: List[str], **kwargs):
        self._general_settings = _general_settings
        self._remote_synchronization_settings = _remote_synchronization_settings
        self._sync_plugins_list = _sync_plugins_list
        self.extra_attrs = kwargs

    @staticmethod
    def from_xml(element: Element) -> "SystemHighAvailabilitySettings":
        """
        Converts XML element to SystemHighAvailabilitySettings instance.
        Args:
            element (Element): XML element representing the afformentioned settings.
        Returns:
            SystemHighAvailabilitySettings: An instance with attributes derived from the XML.
        Processes XML to dict
        """
        general_settings: dict = {
            "disablepreempt": False,
            "disconnectppps": False,
            "pfsyncenabled": False,
            "pfsyncinterface": "lan",
            "pfsyncpeerip": "224.0.0.240"
        }
        remote_synchronization_settings: dict = {
            "synchronizetoip": None,
            "username": None,
            "password": None
        }
        sync_plugins_list: list = []
        xml_settings: dict = xml_utils.etree_to_dict(element)
        for key, value in xml_settings.items():
            if key in general_settings.keys():
                general_settings[key] = value

            elif key in remote_synchronization_settings.keys():
                remote_synchronization_settings[key] = value

            elif key.startswith("synchronize"):
                plugin_name = key[len("synchronize"):]
                sync_plugins_list.append(plugin_name)

        return SystemHighAvailabilitySettings(general_settings, remote_synchronization_settings, sync_plugins_list)

    def to_etree(self) -> Element:
        """
        Serializes the settings to an XML element
        Returns:
            Element: XML representation of the settings.
        Creates an XML element
        """
        main_element = Element("hasync")
        for plugin_name in self._sync_plugins_list:
            SubElement(main_element, f"synchronize{plugin_name}").text = "on"
        for key, value in self._general_settings.items():
            SubElement(main_element, key).text = value
        for key, value in self._remote_synchronization_settings.items():
            SubElement(main_element, key).text = value

        return main_element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "SystemHighAvailabilitySettings":
        """
        Creates an instance from Ansible module parameters.
        Args:
            params (dict): Parameters from an Ansible module.
        Returns:
            User: An instance of InterfaceAssignment.
        Filters out None values from the provided parameters and uses them to
        instantiate the class, focusing on 'identifier', 'device', and 'descr'.
        """

        general_settings: dict = {
            "disablepreempt": False,
            "disconnectppps": False,
            "pfsyncenabled": params.get("synchronize_states"),
            "pfsyncinterface ": params.get("synchronize_interface"),
            "pfsyncpeerip": params.get("synchronize_peer_ip")
        }

        remote_synchronization_settings: dict = {
            "synchronizetoip": params.get("synchronize_config_to_ip"),
            "username": params.get("remote_system_username"),
            "password": params.get("remote_system_password"),
        }
        sync_plugins_list: list = params.get("services_to_synchronize")
        if sync_plugins_list is None:
            sync_plugins_list = []

        return cls(general_settings, remote_synchronization_settings, sync_plugins_list)


class SettingsManager(OPNsenseModuleConfig):
    """
    Manages Settings concerning high availability for OPNsense configurations.

    Inherits from OPNsenseModuleConfig, offering methods for managing
    interface assignments within an OPNsense config file.
    Attributes:
        _settings (SystemHighAvailabilitySettings)
    Methods:
        __init__(self, path="/conf/config.xml"): Initializes class and loads settings.
        _load_interfaces() -> List["Interface_assignment"]: Loads interface assignments from config.
        changed() -> bool: Checks if current assignments differ from the loaded ones.
        update(InterfaceAssignment: InterfaceAssignment): Updates an assignment,
        errors if not found.
        find(**kwargs) -> Optional[InterfaceAssignment]: Finds an assignment matching
        specified attributes.
        save() -> bool: Saves changes to the config file if there are modifications.
    """
    _settings: SystemHighAvailabilitySettings

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="system_high_availability_settings",
            config_context_names=["system_high_availability_settings"],
            path=path,
        )

        self._config_xml_tree = self._load_config()
        self._settings = self._load_settings()

    def __contains__(self, setting_name: str) -> bool:
        """
        Evaluates whether a specific configuration setting exists in the config.

        Parameters:
        - setting_name (str): The name of the setting to check.

        Returns:
        - bool: True if the setting exists, False if not.
        """
        for cfg_map in self._config_maps.values():
            if setting_name in cfg_map:
                return True
        return False

    def _load_settings(self) -> "SystemHighAvailabilitySettings":
        if "hasync" in self:
            element_tree_settings: Element = self.get("hasync")
            return SystemHighAvailabilitySettings.from_xml(element_tree_settings)
        else:
            general_settings: dict = {
                "disablepreempt": False,
                "disconnectppps": False,
                "pfsyncenabled": False,
                "pfsyncinterface ": "lan",
                "pfsyncpeerip": "224.0.0.240"
            }
            remote_synchronization_settings: dict = {
                "synchronizetoip": None,
                "username": None,
                "password": None
            }
            sync_plugins_list: list = []
            return SystemHighAvailabilitySettings(general_settings, remote_synchronization_settings, sync_plugins_list)

    @property
    def changed(self) -> bool:
        """
        Evaluates whether there have been changes to the settings that are not yet reflected in the
        saved system configuration. This property serves as a check to determine if updates have been
        made in memory to the high availability settings that differ from what is currently persisted in the
        system's configuration files.
            Returns:
            bool: True if there are changes to the user or group configurations that have not been
                persisted yet; False otherwise.
            The method works by comparing the current in-memory representations of users and groups
        against the versions loaded from the system's configuration files. A difference in these
        lists indicates that changes have been made in the session that have not been saved, thus
        prompting the need for a save operation to update the system configuration accordingly.
            Note:
            This property should be consulted before performing a save operation to avoid
            unnecessary writes to the system configuration when no changes have been made.
        """

        return bool(str(self._settings) != str(self._load_settings()))

    def update(self) -> None:
        pass

    def save(self) -> bool:
        """
        Saves the current settings to the OPNsense configuration file.
        Checks if there have been changes made to the sync settings. If not, it
        returns False indicating no need to save. If there have, it updates the config accordingly.
        the configuration file and reloads the configuration to reflect changes.
        Returns:
            bool: True if changes were saved successfully, False if no changes were detected.
        """
        if not self.changed:
            return False
        parent_element = self._config_xml_tree.find(
            self._config_maps["settings"]
        )
        for element in list(parent_element):
            parent_element.remove(element)

        # Now, add settings
        parent_element.extend(self._settings.to_etree())

        # Write the updated XML tree to the file
        tree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        return True
