#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
interfaces_configuration_utils module_utils: Module_utils to configure OPNsense interfaces.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


from xml.etree.ElementTree import Element, SubElement

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


class OPNSenseDeviceNotFoundError(Exception):
    """
    Exception raised when a Device is not found.
    """


class OPNSenseDeviceAlreadyAssignedError(Exception):
    """
    Exception raised when a Device is already assigned to an Interface
    """


class OPNSenseInterfaceNotFoundError(Exception):
    """
    Exception raised when an Interface is not found.
    """


class OPNSenseGetInterfacesError(Exception):
    """
    Exception raised if the function can't query the local device
    """


@dataclass
class InterfaceConfiguration:
    """
    Represents a network interface with optional description and extra attributes.

    Attributes:
        identifier (str): Unique ID for the interface.
        extra_attrs (Dict[str, Any]): Additional attributes for configuration.

    Methods:
        __init__: Initializes with ID, device, and optional description.
        from_xml: Creates an instance from XML.
        to_etree: Serializes instance to XML, handling special cases.
        from_ansible_module_params: Creates from Ansible params.
    """

    identifier: str

    # since only the above attributes are needed, the rest is handled here
    extra_attrs: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __init__(
        self,
        identifier: str,
        **kwargs
    ):
        self.identifier = identifier
        self.extra_attrs = kwargs or {}

    @staticmethod
    def from_xml(element: Element) -> "InterfaceConfiguration":
        """
        Converts XML element to a dictionary representing the interface configuration.

        Args:
            element (Element): XML element representing interfaces.

        Returns:
            InterfaceConfiguration: Instance of InterfaceConfiguration.
        """
        try:
            interface_configuration_dict: dict = xml_utils.etree_to_dict(element)
        except Element.ParseError as e:
            raise ValueError(f"Failed to parse XML: {e}") from e

        # Extract identifier
        identifier = list(interface_configuration_dict.keys())[0]
        interface_data = interface_configuration_dict[identifier]
        extra_attrs = {}

        # Translate boolean values and collect extra attributes
        for key, value in interface_data.items():
            if value == "1":
                extra_attrs[key] = True
            elif value == "0":
                extra_attrs[key] = False
            else:
                extra_attrs[key] = value

        # Create the InterfaceConfiguration instance
        interface_configuration = InterfaceConfiguration(
            identifier=identifier,
            **extra_attrs,  # Include all other attributes
        )

        return interface_configuration

    def to_etree(self) -> Element:
        """
        Serializes the instance to an XML Element, including extra attributes.

        Returns:
            Element: XML representation of the instance.

        Creates an XML element with identifier, device, and description. Handles
        serialization of additional attributes, excluding specified exceptions and
        handling specific attribute cases like alias and DHCP options. Assumes
        boolean values translate to '1' for true.
        """

        # Create the main element
        main_element = Element(self.identifier)
        if "device" in self.extra_attrs:
            self.extra_attrs["if"] = self.extra_attrs.pop("device")

        # Serialize extra attributes
        for key, value in self.extra_attrs.items():
            if key in ["identifier", "device"]:
                continue  # Skip these as they are already handled

            xml_key = key
            # options for adv_dhcp... or internal_dynamic configs are written with '_' to the XML
            if not key.startswith("adv_dhcp_") and not key == "internal_dynamic":
                xml_key = key.replace("_", "-")

            if isinstance(value, bool):
                if value == 1:  # Only add if the value is True
                    SubElement(main_element, xml_key).text = "1"
                elif value is False or value == 0:
                    SubElement(main_element, xml_key).text = "0"
            else:
                SubElement(main_element, xml_key).text = value
        return main_element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "InterfaceConfiguration":
        """
        Creates an instance from Ansible module parameters.

        Args:
            params (dict): Parameters from an Ansible module.

        Returns:
            User: An instance of InterfaceConfiguration.

        Creates an InterfaceConfiguration from the ansible Parameters.
        """
        identifier = params.pop("identifier")
        extra_attrs = {}
        if "device" in params:
            params["if"] = params.pop("device")
        for key, value in params.items():
            if key not in ["state"]:
                if isinstance(value, bool):
                    extra_attrs[key] = value
                elif value is not None:
                    extra_attrs[key] = str(value)

        return cls(identifier, **extra_attrs)


class InterfacesSet(OPNsenseModuleConfig):
    """
    Manages network interface configurations for OPNsense configurations.

    Inherits from OPNsenseModuleConfig, offering methods for managing
    interface configuration within an OPNsense config file.

    Attributes:
        _interfaces_configuration (List[InterfaceConfiguration]): List of interface configurations.

    Methods:
        __init__(self, path="/conf/config.xml"): Initializes InterfacesSet and loads interfaces.
        _load_interfaces() -> List["interface_configuration"]: Loads interfaces from config.
        changed() -> bool: Checks if current configurations differ from the loaded ones.
        update(InterfaceConfiguration: InterfaceConfiguration): Updates a configuration,
        errors if not found.
        find(**kwargs) -> Optional[InterfaceConfiguration]: Finds a configuration matching
        specified attributes.
        save() -> bool: Saves changes to the config file if there are modifications.
    """

    _interfaces_configuration: List[InterfaceConfiguration]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="interfaces_configuration",
            config_context_names=["interfaces_configuration"],
            path=path,
        )

        self._config_xml_tree = self._load_config()
        self._interfaces_configuration = self._load_interfaces()

    def _load_interfaces(self) -> List["InterfaceConfiguration"]:
        element_tree_interfaces: Element = self.get("interfaces")

        return [
            InterfaceConfiguration.from_xml(element_tree_interface)
            for element_tree_interface in element_tree_interfaces
        ]

    @property
    def changed(self) -> bool:
        """
        Evaluates whether there have been changes to interface configurations that are not yet
        reflected in the saved system configuration. This property serves as a check to determine
        if updates have been made in memory to the interface configurations that differ from what is
        currently persisted in the system's configuration files.

        Returns:
            bool: True if there are changes to the interface configurations that have not been
                persisted yet; False otherwise.
        """

        current_interfaces = self._interfaces_configuration
        saved_interfaces = self._load_interfaces()

        if len(current_interfaces) != len(saved_interfaces):
            return True

        for current, saved in zip(current_interfaces, saved_interfaces):
            if (
                current.identifier != saved.identifier
                or current.extra_attrs != saved.extra_attrs
            ):
                return True

        return False

    def get_interfaces(self) -> List[InterfaceConfiguration]:
        """
        Retrieves a list of interface confiugrations from an OPNSense device via a PHP function.

        The function queries the device using specified PHP requirements and config functions.
        It processes the stdout, extracts interface data, and handles errors.

        Returns:
            list[InterfaceConfiguration]: A list of interface configurations parsed
                                       from the PHP function's output.

        Raises:
            OPNSenseGetInterfacesError: If an error occurs during the retrieval
                                        or parsing process,
                                        or if no interfaces are found.
        """

        # load requirements
        php_requirements = self._config_maps["interfaces_configuration"][
            "php_requirements"
        ]
        php_command = """
                    /* get physical network interfaces */
                    foreach (get_interface_list() as $key => $item) {
                        echo $key.',';
                    }
                    /* get virtual network interfaces */
                    foreach (plugins_devices() as $item){
                        foreach ($item["names"] as $key => $if ) {
                            echo $key.',';
                        }
                    }
                    """

        # run php function
        result = opnsense_utils.run_command(
            php_requirements=php_requirements,
            command=php_command,
        )

        # check for stderr
        if result.get("stderr"):
            raise OPNSenseGetInterfacesError(
                "error encounterd while getting interfaces"
            )

        # parse list
        interface_list: list[str] = [
            item.strip()
            for item in result.get("stdout").split(",")
            if item.strip() and item.strip() != "None"
        ]

        # check parsed list length
        if len(interface_list) < 1:
            raise OPNSenseGetInterfacesError(
                "error encounterd while getting interfaces, less than one interface available"
            )

        return interface_list

    def add_or_update(self, interface_configuration: InterfaceConfiguration) -> None:
        """
        Adds a new interface to the configuration or updates an existing one.

        Args:
            interface_configuration (InterfaceConfiguration): The interface to add or update.

        Raises:
            OPNSenseInterfaceNotFoundError: If the interface configuration is not found.
            OPNSenseDeviceAlreadyAssignedError: If the device is already assigned
                to another interface.
        """

        device_interfaces_set: set = set(self.get_interfaces())

        # check if the input interface name is a valid interface on the device
        new_if_config_device: Optional[str] = interface_configuration.extra_attrs.get("if", None)

        if new_if_config_device not in device_interfaces_set:
            raise OPNSenseInterfaceNotFoundError(
                "Interface was not found on OPNsense Instance!"
            )

        # check if the input interface is already assigned to another if-config
        existing_if_configs = list(filter(lambda if_cfg: if_cfg.extra_attrs.get("if", None) == new_if_config_device, self._interfaces_configuration))

        # if an existing interface config with the dame 'if' but a different identifier is detected
        # then we cannot allow a reassignment of a physical device to another interface and therefore
        # raise an exception
        if len(existing_if_configs) and existing_if_configs[0].identifier != interface_configuration.identifier:
            raise OPNSenseDeviceAlreadyAssignedError(
                "This device is already assigned, please unassign this device first"
            )

        existing_id_configs = list(filter(lambda if_cfg: if_cfg.identifier == interface_configuration.identifier, self._interfaces_configuration))

        if len(existing_id_configs):
            # update
            existing_id_configs[0].extra_attrs.update(**interface_configuration.extra_attrs)
        else:
            # add
            self._interfaces_configuration.append(interface_configuration)

    def remove(self, interface_configuration: InterfaceConfiguration) -> None:
        """
        Removes an interface configuration from the configuration.

        Args:
            interface_configuration (InterfaceConfiguration): The interface configuration to remove.

        Raises:
            OPNSenseInterfaceNotFoundError: If the interface configuration is not found.
        """
        if interface_configuration in self._interfaces_configuration:
            self._interfaces_configuration.remove(interface_configuration)
        else:
            raise OPNSenseInterfaceNotFoundError(
                f"Interface {interface_configuration.identifier} not found."
            )  # pylint: disable=C0301

    def find(self, **kwargs) -> Optional[InterfaceConfiguration]:
        """
        Searches for an interface configuration that matches given criteria.

        Iterates through the list of interface configurations, checking if each one
        matches all provided keyword arguments. If a match is found, returns the
        corresponding interface configuration. If no match is found, returns None.

        Args:
            **kwargs: Key-value pairs to match against attributes of interface configurations.

        Returns:
            Optional[InterfaceConfiguration]: The first interface configuration that matches
            the criteria, or None if no match is found.
        """
        identifier_match: Optional[List[InterfaceConfiguration]] = None
        if "identifier" in kwargs:
            identifier_match = list(filter(lambda ifcfg: ifcfg.identifier == kwargs["identifier"], self._interfaces_configuration))

        if identifier_match and len(identifier_match):
            return identifier_match[0]

        extra_attr_matches: List[InterfaceConfiguration] = list(filter(
            lambda if_cfg: set(kwargs.items()).issubset(set(if_cfg.extra_attrs.items())), self._interfaces_configuration
        ))
        if len(extra_attr_matches) > 1:
            # TODO handle ambiguous matches
            pass

        if len(extra_attr_matches):
            return extra_attr_matches[0]

        return None

    def save(self) -> bool:
        """
        Saves the current state of interface configurations to the OPNsense configuration file.

        Checks if there have been changes to the interface configurations. If not, it
        returns False indicating no need to save. It then locates the parent element
        for interface configurations in the XML tree and replaces existing entries with
        the updated set from memory. After updating, it writes the new XML tree to
        the configuration file and reloads the configuration to reflect changes.

        Returns:
            bool: True if changes were saved successfully, False if no changes were detected.

        Note:
            This method assumes that 'parent_element' correctly refers to the container
            of interface elements within the configuration file.
        """

        if not self.changed:
            return False

        # Use 'find' to get the single parent element
        interfaces_element = self._config_xml_tree.find(
            self._config_maps["interfaces_configuration"]["interfaces"]
        )

        interfaces_element.clear()
        interfaces_element.extend(
            [interface_configuration.to_etree() for interface_configuration in self._interfaces_configuration]
        )

        return super().save(override_changed=True)
