#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import List, Optional, Dict, Any


from xml.etree.ElementTree import Element, ElementTree, SubElement

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


class OPNSenseInterfaceNotFoundError(Exception):
    """
    Exception raised when an OPNsense group is not found.
    """


class OPNSenseDeviceNotFoundError(Exception):
    """
    Exception raised when a Device is not found.
    """


@dataclass
class Interface_assignment:
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
    descr: Optional[str] = None

    # since only the above attributes are needed, the rest is handled here
    extra_attrs: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __init__(
        self,
        identifier: str,
        device: str,
        descr: Optional[str] = None,
        **kwargs,
    ):
        self.identifier = identifier
        self.device = device
        if descr is not None:
            self.descr = descr
        self.extra_attrs = kwargs

    @staticmethod
    def from_xml(element: Element) -> "Interface_assignment":
        """
        Converts XML element to Interface_assignment instance.

        Args:
            element (Element): XML element representing an interface.

        Returns:
            Interface_assignment: An instance with attributes derived from the XML.

        Processes XML to dict, assigning 'identifier' and 'device' from keys and
        'if' element. Assumes single key processing.
        """

        interface_assignment_dict: dict = xml_utils.etree_to_dict(element)

        for key, value in interface_assignment_dict.items():
            value["identifier"] = key  # Move the key to a new "identifier" field
            if "if" in value:
                if_key = value.pop("if", None)
                if if_key is not None:
                    value["device"] = if_key
            break  # Only process the first key, assuming there's only one

        # Return only the content of the dictionary without the key
        return Interface_assignment(**interface_assignment_dict.popitem()[1])

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

        interface_assignment_dict: dict = asdict(self)

        exceptions = ["dhcphostname", "mtu", "subnet", "gateway", "media", "mediaopt"]

        # Create the main element
        main_element = Element(interface_assignment_dict["identifier"])

        # Special handling for 'device' and 'descr'
        SubElement(main_element, "if").text = interface_assignment_dict.get("device")
        SubElement(main_element, "descr").text = interface_assignment_dict.get("descr")

        # handle special cases
        if getattr(self, "alias-subnet", None):
            interface_assignment_dict["extra_attrs"]["alias-subnet"] = getattr(
                self, "alias-subnet", None
            )

            interface_assignment_dict["extra_attrs"]["alias-address"] = getattr(
                self, "alias-address", None
            )

        if getattr(self, "dhcp6-ia-pd-len", None):
            interface_assignment_dict["extra_attrs"]["dhcp6-ia-pd-len"] = getattr(
                self, "dhcp6-ia-pd-len", None
            )

        if getattr(self, "track6-interface", None):
            interface_assignment_dict["extra_attrs"]["track6-interface"] = getattr(
                self, "track6-interface", None
            )

        if getattr(self, "track6-prefix-id", None):
            interface_assignment_dict["extra_attrs"]["track6-prefix-id"] = getattr(
                self, "track6-prefix-id", None
            )

        # Serialize extra attributes
        for key, value in interface_assignment_dict["extra_attrs"].items():
            if (
                key
                in [
                    "spoofmac",
                    "alias-address",
                    "alias-subnet",
                    "dhcp6-ia-pd-len",
                    "adv_dhcp_pt_timeout",
                    "adv_dhcp_pt_retry",
                    "adv_dhcp_pt_select_timeout",
                    "adv_dhcp_pt_reboot",
                    "adv_dhcp_pt_backoff_cutoff",
                    "adv_dhcp_pt_initial_interval",
                    "adv_dhcp_pt_values",
                    "adv_dhcp_send_options",
                    "adv_dhcp_request_options",
                    "adv_dhcp_required_options",
                    "adv_dhcp_option_modifiers",
                    "adv_dhcp_config_advanced",
                    "adv_dhcp_config_file_override",
                    "adv_dhcp_config_file_override_path",
                    "dhcprejectfrom",
                    "track6-interface",
                    "track6-prefix-id",
                ]
                and value is None
            ):
                sub_element = SubElement(main_element, key)
            if value is None and key not in exceptions:
                continue
            sub_element = SubElement(main_element, key)
            if value is True:
                sub_element.text = "1"
            elif value is not None:
                sub_element.text = str(value)

        return main_element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "User":
        """
        Creates an instance from Ansible module parameters.

        Args:
            params (dict): Parameters from an Ansible module.

        Returns:
            User: An instance of Interface_assignment.

        Filters out None values from the provided parameters and uses them to
        instantiate the class, focusing on 'identifier', 'device', and 'descr'.
        """

        interface_assignment_dict = {
            "identifier": params.get("identifier"),
            "device": params.get("device"),
            "descr": params.get("description"),
        }

        interface_assignment_dict = {
            key: value for key, value in interface_assignment_dict.items() if value is not None
        }

        return cls(**interface_assignment_dict)


class InterfacesSet(OPNsenseModuleConfig):

    _interfaces_assignments: List[Interface_assignment]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="interfaces_assignments",
            config_context_names=["interfaces_assignments"],
            path=path,
        )

        self._interfaces_assignments = self._load_interfaces()

    def _load_interfaces(self) -> List["Interface_assignment"]:

        element_tree_interfaces: Element = self.get("interfaces")

        return [
            Interface_assignment.from_xml(element_tree_interface)
            for element_tree_interface in element_tree_interfaces
        ]

    @property
    def changed(self) -> bool:

        return self._load_interfaces() != self._interfaces_assignments

    def update(self, interface_assignment: Interface_assignment) -> None:

        # Check if device exists first
        if interface_assignment.device not in [
            assignment.device for assignment in self._interfaces_assignments
        ]:
            raise OPNSenseDeviceNotFoundError("Device was not found on OpnSense Instance!")

        try:
            # Find the interface to update
            interface_to_update: Optional[Interface_assignment] = next(
                interface
                for interface in self._interfaces_assignments
                if interface.identifier == interface_assignment.identifier
            )

            # Merge extra_attrs
            interface_assignment.extra_attrs.update(interface_to_update.extra_attrs)

            # Update the existing interface
            interface_to_update.__dict__.update(interface_assignment.__dict__)

        except StopIteration as error_message:
            # Handle case where interface is not found
            raise OPNSenseInterfaceNotFoundError(
                f"Interface not found for update error: {error_message}"
            )

    def find(self, **kwargs) -> Optional[Interface_assignment]:
        """ """

        for interface_assignment in self._interfaces_assignments:
            match = all(
                getattr(interface_assignment, key, None) == value for key, value in kwargs.items()
            )
            if match:
                return interface_assignment
        return None

    def save(self) -> bool:
        if not self.changed:
            return False

        # Use 'find' to get the single parent element, not 'findall'
        parent_element = self._config_xml_tree.find(
            self._config_maps["interfaces_assignments"]["interfaces"]
        )

        # raise Exception(f"new: {[(element.tag, element.text) for element in parent_element[2]]}")

        # Assuming 'parent_element' correctly refers to the container of interface elements
        for interface_element in list(parent_element):
            parent_element.remove(interface_element)

        # Now, add updated interface elements
        parent_element.extend(
            [
                interface_assignment.to_etree()
                for interface_assignment in self._interfaces_assignments
            ]
        )

        # Write the updated XML tree to the file
        tree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        # Reload the configuration to reflect the updated changes
        self._config_xml_tree = self._load_config()

        return True
