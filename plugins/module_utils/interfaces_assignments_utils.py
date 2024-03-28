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


class OPNSenseInterfaceNotEnabledError(Exception):
    """
    Exception raised when a not valid base32 api code is provided
    """


@dataclass
class Interface_assignment:
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

        interface_assignment_dict: dict = asdict(self)

        exceptions = ["dhcphostname", "mtu", "subnet", "gateway", "media", "mediaopt"]

        # Create the main element
        main_element = Element(interface_assignment_dict["identifier"])

        # Special handling for 'device' and 'descr'
        SubElement(main_element, "if").text = interface_assignment_dict.get("device")
        SubElement(main_element, "descr").text = interface_assignment_dict.get("descr")

        # Serialize extra attributes
        for key, value in interface_assignment_dict["extra_attrs"].items():
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

        try:
            interface_to_update: Optional[Interface_assignment] = next(
                interface
                for interface in self._interfaces_assignments
                if interface.identifier == interface_assignment.identifier
            )

            # merge extra_attrs
            interface_assignment.extra_attrs.update(interface_to_update.extra_attrs)

            # update the existing interface
            interface_to_update.__dict__.update(interface_assignment.__dict__)

        except StopIteration as exec:
            # Handle case where interface is not found
            raise OPNSenseInterfaceNotFoundError("Interface not found for update")

    def save(self) -> bool:

        if not self.changed:
            return False

        # Assuming self._config_maps["system_access_users"]["system"] gives you the path to the 'system' element
        filter_element: Element = self._config_xml_tree.findall(
            self._config_maps["interfaces_assignments"]["interfaces"]
        )

        for interface in filter_element:
            filter_element.remove(interface)

        filter_element.extend(
            [
                Interface_assignment.to_etree()
                for Interface_assignment in self._interfaces_assignments
            ]
        )

        # Write the updated XML tree to the file
        tree: ElementTree = ElementTree(self._config_xml_tree)

        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        # Reload the configuration to reflect the updated changes
        self._config_xml_tree = self._load_config()

        return True
