#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utilities for alias related operations.
"""
from typing import List, Optional

from xml.etree.ElementTree import Element, ElementTree
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.enum_utils import ListEnum


class IPProtocol(ListEnum):
    """Represents the IPProtocol."""

    IPv4 = "IPv4"
    IPv6 = "IPv6"


class FirewallAliasType(ListEnum):
    """
    some docstring
    """

    HOSTS = "host"
    NETWORKS = "network"
    PORTS = "port"
    URLS = "url"
    URLTABLES = "urltable"
    GEOIP = "geoip"
    NETWORKGROUP = "networkgroup"
    MACADDRESS = "mac"
    BGPASN = "bgpasn"
    DYNAMICIPV6HOST = "dynipv6host"
    OPNVPNGROUP = "opnvpngroup"
    INTERNAL = "internal"
    EXTERNAL = "external"


class FirewallAlias:
    """
    some docstring
    """

    def __init__(self, **kwargs):
        # set default attributes
        self.uuid: Optional[str] = None
        self.enabled: bool = True
        self.proto: Optional[IPProtocol] = None
        self.counters: Optional[bool] = False
        self.interface: Optional[str] = None
        self.updatefreq: Optional[str] = None
        self.content: Optional[List[str]] = []
        self.name = kwargs.get("name", None)
        self.type: Optional[FirewallAliasType] = None

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __post_init__(self):
        # Manually define the fields and their expected types
        enum_fields = {"type": FirewallAliasType}

        for field_name, field_type in enum_fields.items():
            value = getattr(self, field_name)

            # Check if the value is a string and the field_type is a subclass of ListEnum
            if isinstance(value, str) and issubclass(field_type, ListEnum):
                # Convert string to ListEnum
                setattr(self, field_name, field_type.from_string(value))

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
            counters=firewall_alias_dict.get("counters", "0") == "1",
        )

        # process attribute content to a list
        if firewall_alias_dict.get("content"):
            firewall_alias_dict["content"] = [
                line.strip()
                for line in firewall_alias_dict["content"].splitlines()
                if line.strip()
            ]

        return FirewallAlias(**firewall_alias_dict)

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "FirewallAlias":
        """
        some docstring
        """

        firewall_alias_dict: dict = {
            "enabled": params.get("enabled"),
            "name": params.get("name"),
            "type": FirewallAliasType(params.get("type")),
            "categories": params.get("categories"),
            "content": params.get("content"),
            "counters": params.get("statistics"),
            "description": params.get("description"),
            "updatefreq": params.get("refreshfrequency"),
        }

        firewall_alias_dict = {
            key: value
            for key, value in firewall_alias_dict.items()
            if value is not None
        }

        return cls(**firewall_alias_dict)

    def to_etree(self) -> Element:
        """
        some docstring
        """

        firewall_alias_dict: dict = self.__dict__.copy()
        del firewall_alias_dict["uuid"]

        # Handle content field if it is a list
        if isinstance(firewall_alias_dict.get("content"), list):
            firewall_alias_dict["content"] = (
                "\n"
                + "\n".join(
                    [f"            {item}" for item in firewall_alias_dict["content"]]
                )
                + "\n            "
            )

        element: Element = xml_utils.dict_to_etree("alias", firewall_alias_dict)[0]

        if self.uuid:
            element.attrib["uuid"] = self.uuid

        return element


class FirewallAliasSet(OPNsenseModuleConfig):
    """
    some docstring
    """

    _aliases: List[FirewallAlias]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="firewall_alias",
            config_context_names=["firewall_alias"],
            path=path,
        )
        self._aliases = self._load_aliases()

    def _load_aliases(self) -> List[FirewallAlias]:
        """
        some doctring
        """

        element_tree_alias: Element = self.get("alias")

        return [FirewallAlias.from_xml(element) for element in element_tree_alias]
