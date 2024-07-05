#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utilities for alias related operations.
"""
from typing import List, Optional

from xml.etree.ElementTree import Element, ElementTree
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils


class FirewallAlias:
    """
    some docstring
    """

    def __init__(self, **kwargs):
        # set default attributes
        self.uuid: Optional[str] = None
        self.enabled: bool = True
        self.proto: Optional[str] = None
        self.counters: Optional[str] = "0"
        self.interface: Optional[str] = None
        self.updatefreq: Optional[str] = None
        self.name = kwargs.get("name", None)

        for key, value in kwargs.items():
            setattr(self, key, value)

    @staticmethod
    def from_xml(element: Element) -> "FirewallAlias":
        """
        some docstring
        """

        firewall_alias_dict: dict = xml_utils.etree_to_dict(element)["alias"]

        # get uuid tag
        firewall_alias_dict.update(
            uuid=element.attrib.get("uuid"),
            enabled=firewall_alias_dict.get("enabled", "0") == "1",
        )

        return FirewallAlias(**firewall_alias_dict)

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "FirewallAlias":
        """
        some docstring
        """

        firewall_alias_dict: dict = {
            "enabled": params.get("enabled"),
            "name": params.get("name"),
            "type": params.get("type"),
            "categories": params.get("categories"),
            "content": params.get("content"),
            "statistics": params.get("statistics"),
            "description": params.get("description"),
        }

        firewall_alias_dict = {
            key: value for key, value in firewall_alias_dict.items() if value is not None
        }

        return cls(**firewall_alias_dict)

    def to_etree(self) -> Element:
        """
        some docstring
        """

        firewall_alias_dict: dict = self.__dict__.copy()
        del firewall_alias_dict["uuid"]

        element: Element = xml_utils.dict_to_etree("alias", firewall_alias_dict)[0]

        if self.uuid:
            element.attrib["uuid"] = self.uuid

        return element
