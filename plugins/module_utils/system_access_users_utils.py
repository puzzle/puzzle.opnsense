#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: disable=too-many-lines

"""
This module manages user and group configurations within an OPNsense system. It provides
functionalities for handling user attributes and group memberships, utilizing data classes and
XML manipulation. Key features include creation, update, and deletion of user records,
secure password management, API key generation, and comprehensive error handling.

Classes:
- `User`: Manages individual user accounts with functionalities such as XML serialization and
  initialization from Ansible module parameters.
- `Group`: Manages group attributes and membership operations with XML interaction capabilities.
- `UserSet`: Handles bulk operations on users and groups, ensuring consistent state across the
  system configuration.

Exceptions are defined for handling specific group and API key validation errors, enhancing
the module's robustness in configuration management tasks.

Designed for Ansible integration, specifically targeting the OPNsense firewall system, this
module provides a structured approach to system access management.

Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
Licensed under the GNU General Public License v3.0+
(see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt).
"""


import dataclasses
from dataclasses import dataclass, asdict, fields, field
from typing import List, Optional, Dict, Any
import base64
import os
import binascii

from xml.etree.ElementTree import Element, ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)


class User:

    def __init__(self, **kwargs):

        # set default attributes
        self.authorizedkeys = kwargs.get("authorizedkeys", None)
        self.expires = kwargs.get("expires", None)
        self.ipsecpsk = kwargs.get("ipsecpsk", None)
        self.otp_seed = kwargs.get("otp_seed", None)

        if "plain_password" in kwargs:
            self.plain_password = kwargs["plain_password"]

        for key, value in kwargs.items():
            setattr(self, key, value)

    @staticmethod
    def from_xml(element: Element) -> "User":

        user_dict: dict = xml_utils.etree_to_dict(element)["user"]
        return User(**user_dict)

    def to_etree(self) -> Element:
        user_dict: dict = {key: value for key, value in self.__dict__.items()}
        element: Element = xml_utils.dict_to_etree("user", user_dict)[0]

        return element
