#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utilities for aliases related operations.
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
        firewall_alias_dict.update(uuid=element.attrib.get("uuid"))

        return FirewallAlias(**firewall_alias_dict)
