#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utilities for alias related operations.
"""
import uuid
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
        self.uuid: Optional[str] = kwargs.get("uuid", str(uuid.uuid4()))
        self.enabled: bool = True
        self.proto: Optional[IPProtocol] = None
        self.counters: Optional[bool] = False
        self.interface: Optional[str] = None
        self.updatefreq: Optional[int] = None
        self.content: Optional[List[str]] = []
        self.name = kwargs.get("name", None)
        self.type: Optional[FirewallAliasType] = None

        for key, value in kwargs.items():
            setattr(self, key, value)

        self.__post_init__()

    def __post_init__(self):
        # Manually define the fields and their expected types
        enum_fields = {"type": FirewallAliasType}

        for field_name, field_type in enum_fields.items():
            value = getattr(self, field_name)

            # Check if the value is a string and the field_type is a subclass of ListEnum
            if isinstance(value, str) and issubclass(field_type, ListEnum):
                # Convert string to ListEnum
                setattr(self, field_name, field_type.from_string(value))

    def __eq__(self, other):
        if isinstance(other, FirewallAlias):
            return self.__dict__ == other.__dict__
        return False

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
        if isinstance(firewall_alias_dict.get("content"), list):
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
            "type": params.get("type"),
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

        for alias_key, alias_val in firewall_alias_dict.copy().items():

            if alias_key in ["enabled", "counters"]:
                firewall_alias_dict[alias_key] = "0" if alias_val is False else "1"
                continue

            if isinstance(alias_val, bool):
                firewall_alias_dict[alias_key] = "0" if alias_val is False else "1"
                continue

            if issubclass(type(alias_val), ListEnum):
                firewall_alias_dict[alias_key] = alias_val.value
                continue

        # Handle content field if it is a list
        if isinstance(firewall_alias_dict.get("content"), list):
            firewall_alias_dict["content"] = (
                "\n"
                + "\n".join([f"{item}" for item in firewall_alias_dict["content"]])
                + "\n"
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

    @property
    def changed(self) -> bool:
        """
        some docstring
        """
        return self._load_aliases() != self._aliases

    def add_or_update(self, alias: FirewallAlias) -> None:
        """
        some docstring.
        """

        existing_alias: Optional[FirewallAlias] = next(
            (a for a in self._aliases if a.name == alias.name), None
        )

        if existing_alias:
            alias.__dict__.pop("uuid")
            existing_alias.__dict__.update(alias.__dict__)
        else:
            self._aliases.append(alias)

    def delete(self, alias: FirewallAlias) -> bool:
        """
        some docstring
        """

        existing_alias: Optional[FirewallAlias] = next(
            (a for a in self._aliases if a.name == alias.name), None
        )

        if existing_alias:
            self._aliases.remove(existing_alias)
            return True
        return False

    def save(self) -> bool:
        """
        some doctsring
        """

        if not self.changed:
            return False

        filter_element: Element = self._config_xml_tree.find(
            self._config_maps[self._module_name]["alias"]
        )

        # Remove specific child elements (e.g., 'alias') from filter_element
        for alias_element in list(
            filter_element.findall("alias")
        ):  # Use list() to avoid modification during iteration
            filter_element.remove(alias_element)

        # Now, add the updated elements back directly to filter_element
        filter_element.extend([alias.to_etree() for alias in self._aliases])

        # Write the updated XML tree to the file
        tree: ElementTree = ElementTree(self._config_xml_tree)

        # raise ValueError([(test.tag, test.text) for test in list(filter_element)[0]])

        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        # Reload the configuration to reflect the updated changes

        self._config_xml_tree = self._load_config()

        return True
