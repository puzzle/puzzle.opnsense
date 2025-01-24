#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
interfaces_configuration_utils module_utils: Module_utils to configure OPNsense interface configurations
"""

from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any


from xml.etree.ElementTree import Element, ElementTree, SubElement

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
        device (str): Device name.
        descr (Optional[str]): Description of the interface.
        extra_attrs (Dict[str, Any]): Additional attributes for configuration.

    Methods:
        __init__: Initializes with ID, device, and optional description.
        from_xml: Creates an instance from XML.
        to_etree: Serializes instance to XML, handling special cases.
        from_ansible_module_params: Creates from Ansible params.
    """

    identifier: str
    device: str

    # since only the above attributes are needed, the rest is handled here
    extra_attrs: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __init__(
        self,
        identifier: str,
        device: str,
        extra_attrs: Dict[str, Any] = None,
        **kwargs,
    ):
        self.identifier = identifier
        self.device = device
        self.extra_attrs = extra_attrs or {}

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
            raise ValueError(f"Failed to parse XML: {e}")

        # Extract identifier and device
        identifier = list(interface_configuration_dict.keys())[0]
        interface_data = interface_configuration_dict[identifier]
        device = interface_data.pop("if", None)
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
            device=device,
            extra_attrs=extra_attrs  # Include all other attributes
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

        # Ensure the instance attributes are accessed correctly
        interface_configuration_dict: dict = asdict(self)

        # Create the main element
        main_element = Element(interface_configuration_dict["identifier"])
        SubElement(main_element, "if").text = interface_configuration_dict.get("device")

        # Serialize extra attributes
        for key, value in interface_configuration_dict["extra_attrs"].items():
            # if key in ["identifier", "device"]:
            #     continue  # Skip these as they are already handled
            if value is True:
                SubElement(main_element, key).text = "1"
            elif value is False:
                continue
                # SubElement(main_element, key).text = "0"
            elif value is not None:
                SubElement(main_element, key).text = value

        return main_element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "InterfaceConfiguration":
        """
        Creates an instance from Ansible module parameters.

        Args:
            params (dict): Parameters from an Ansible module.

        Returns:
            User: An instance of InterfaceConfiguration.

        Filters out None values from the provided parameters and uses them to
        instantiate the class, focusing on 'identifier', 'device', and 'descr'.
        """

        # interface_configuration_dict = {
        #     "identifier": params.get("identifier"),
        #     "device": params.get("device"),
        # }
        device = params.get("device")
        identifier = params.get("identifier")
        # interface_configuration_dict = {
        #     key: value
        #     for key, value in interface_configuration_dict.items()
        #     if value is not None
        # }
        extra_attrs = {}
        for key, value in params.items():
            if value is not None and key not in [
                "identifier",
                "device",
                "ipv4_configuration_type",
                "ipv6_configuration_type",
                "state",
            ]:
                extra_attrs[key] = value

        return cls(identifier,device,extra_attrs)


class InterfacesSet(OPNsenseModuleConfig):
    """
    Manages network interface assignments for OPNsense configurations.

    Inherits from OPNsenseModuleConfig, offering methods for managing
    interface assignments within an OPNsense config file.

    Attributes:
        _interfaces_configuration (List[InterfaceConfiguration]): List of interface assignments.

    Methods:
        __init__(self, path="/conf/config.xml"): Initializes InterfacesSet and loads interfaces.
        _load_interfaces() -> List["interface_configuration"]: Loads interface assignments from config.
        changed() -> bool: Checks if current assignments differ from the loaded ones.
        update(InterfaceConfiguration: InterfaceConfiguration): Updates an assignment,
        errors if not found.
        find(**kwargs) -> Optional[InterfaceConfiguration]: Finds an assignment matching
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
            if current.identifier != saved.identifier or \
            current.device != saved.device or \
            current.extra_attrs != saved.extra_attrs:
                return True

        return False

    def get_interfaces(self) -> List[InterfaceConfiguration]:
        """
        Retrieves a list of interface assignments from an OPNSense device via a PHP function.

        The function queries the device using specified PHP requirements and config functions.
        It processes the stdout, extracts interface data, and handles errors.

        Returns:
            list[InterfaceConfiguration]: A list of interface assignments parsed
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

    def add(self, interface_configuration: InterfaceConfiguration) -> None:
        """
        Adds an interface assignment in the set.

        Checks for device existence and updates or raises errors accordingly.

        Args:
            interface_configuration (InterfaceConfiguration): The interface assignment to update.

        Raises:
            OPNSenseDeviceNotFoundError: If device is not found.
        """

        device_list_set: set = set(  # pylint: disable=R1718
            [assignment.device for assignment in self._interfaces_configuration]
        )

        identifier_list_set: set = set(  # pylint: disable=R1718
            [assignment.identifier for assignment in self._interfaces_configuration]
        )

        device_interfaces_set: set = set(self.get_interfaces())

        free_interfaces = device_interfaces_set - device_list_set

        if interface_configuration.device not in device_interfaces_set:
            raise OPNSenseDeviceNotFoundError(
                "Device was not found on OPNsense Instance!"
            )

        interface_to_update: Optional[InterfaceConfiguration] = next(
            (
                interface
                for interface in self._interfaces_configuration
                if interface.device == interface_configuration.device
                or interface.identifier == interface_configuration.identifier
            ),
            None,
        )

        if not interface_to_update:

            interface_to_create: InterfaceConfiguration = InterfaceConfiguration(
                identifier=interface_configuration.identifier,
                device=interface_configuration.device,
                extra_attrs=interface_configuration.extra_attrs,
            )

            self._interfaces_configuration.append(interface_to_create)

            return
        else:
            raise OPNSenseDeviceAlreadyAssignedError(
                "This device is already assigned, please unassign this device first"
            )
    
    def update(self, interface_configuration: InterfaceConfiguration) -> None:
        """
        Updates an existing interface assignment in the configuration.

        Args:
            interface_configuration (InterfaceConfiguration): The interface configuration to update.

        Raises:
            OPNSenseInterfaceNotFoundError: If the interface configuration is not found.
            OPNSenseDeviceAlreadyAssignedError: If the device is already assigned to another interface.
        """
        device_list_set: set = set([assignment.device for assignment in self._interfaces_configuration])
        identifier_list_set: set = set([assignment.identifier for assignment in self._interfaces_configuration])
        device_interfaces_set: set = set(self.get_interfaces())
        free_interfaces = device_interfaces_set - device_list_set

        if interface_configuration.device not in device_interfaces_set:
            raise OPNSenseInterfaceNotFoundError("Interface was not found on OPNsense Instance!")

        interface_to_update: Optional[InterfaceConfiguration] = next(
            (
                interface
                for interface in self._interfaces_configuration
                if interface.device == interface_configuration.device
                or interface.identifier == interface_configuration.identifier
            ),
            None,
        )

        if not interface_to_update:
            raise OPNSenseInterfaceNotFoundError(f"Interface {interface_configuration.identifier} not found.")

        if interface_configuration.device in free_interfaces or interface_configuration.device == interface_to_update.device:
            if interface_configuration.identifier in identifier_list_set:
                # Merge extra_attrs
                interface_configuration.extra_attrs.update(interface_to_update.extra_attrs)
                # Update the existing interface
                interface_to_update.__dict__.update(interface_configuration.__dict__)
            else:
                raise OPNSenseDeviceAlreadyAssignedError("This device is already assigned, please unassign this device first")
        else:
            raise OPNSenseDeviceAlreadyAssignedError("This device is already assigned, please unassign this device first")

    def remove(self, interface_configuration: InterfaceConfiguration) -> None:
        """
        Removes an interface assignment from the configuration.

        Args:
            interface_configuration (InterfaceConfiguration): The interface configuration to remove.

        Raises:
            OPNSenseInterfaceNotFoundError: If the interface configuration is not found.
        """
        if interface_configuration in self._interfaces_configuration:
            self._interfaces_configuration.remove(interface_configuration)
        else:
            raise OPNSenseInterfaceNotFoundError(f"Interface {interface_configuration.identifier} not found.")   
          
    def find(self, **kwargs) -> Optional[InterfaceConfiguration]:
        """
        Searches for an interface assignment that matches given criteria.

        Iterates through the list of interface assignments, checking if each one
        matches all provided keyword arguments. If a match is found, returns the
        corresponding interface assignment. If no match is found, returns None.

        Args:
            **kwargs: Key-value pairs to match against attributes of interface assignments.

        Returns:
            Optional[InterfaceConfiguration]: The first interface assignment that matches
            the criteria, or None if no match is found.
        """

        for interface_configuration in self._interfaces_configuration:
            match = all(
                getattr(interface_configuration, key, None) == value
                for key, value in kwargs.items()
            )
            if match:
                return interface_configuration
        return None

    def save(self) -> bool:
        """
        Saves the current state of interface assignments to the OPNsense configuration file.

        Checks if there have been changes to the interface assignments. If not, it
        returns False indicating no need to save. It then locates the parent element
        for interface assignments in the XML tree and replaces existing entries with
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
        parent_element = self._config_xml_tree.find(
            self._config_maps["interfaces_configuration"]["interfaces"]
        )

        # Assuming 'parent_element' correctly refers to the container of interface elements
        for interface_element in list(parent_element):
            parent_element.remove(interface_element)

        # Now, add updated interface elements
        parent_element.extend(
            [
                interface_configuration.to_etree()
                for interface_configuration in self._interfaces_configuration
            ]
        )

        # Write the updated XML tree to the file
        tree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        return True
