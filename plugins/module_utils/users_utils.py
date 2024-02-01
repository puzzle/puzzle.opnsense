#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from dataclasses import dataclass, asdict, fields
from enum import Enum
from typing import List, Optional, Any

from xml.etree.ElementTree import Element, ElementTree
import os
import hashlib
import base64
import subprocess

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
    version_utils,
    module_index,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    UnsupportedOPNsenseVersion,
    UnsupportedVersionForModule,
)


@dataclass
class User:
    """Used to represent an User."""

    name: str
    password: str
    scope: str
    descr: Optional[str] = None
    ipsecpsk: Optional[str] = None
    otp_seed: Optional[str] = None
    shell: Optional[str] = None
    uid: Optional[str] = None
    disabled: bool = False
    full_name: Optional[str] = None
    email: Optional[str] = None
    comment: Optional[str] = None
    landing_page: Optional[str] = None
    expires: Optional[str] = None
    authorizedkeys: Optional[str] = None
    cert: Optional[str] = None  # TODO is in another xml path
    api_keys_item_api_key: Optional[str] = None
    groupname: Optional[str] = None

    def __eq__(self, other) -> bool:
        if not isinstance(other, User):
            return False

        for field in fields(self):
            if field.name != "password" and field.name != "uid":
                if getattr(self, field.name) != getattr(other, field.name):
                    return False

        return True

    def to_etree(self) -> Element:
        """ """

        user_dict: dict = asdict(self)

        for user_key, user_val in user_dict.copy().items():
            if user_val is None and user_key in [
                "expires",
                "authorizedkeys",
                "ipsecpsk",
                "otp_seed",
            ]:
                continue

            elif user_val is None or user_val is False:
                del user_dict[user_key]
                continue

        element: Element = xml_utils.dict_to_etree("user", user_dict)[0]

        return element

    def _set_password(password: str) -> str:
        # get version
        _opnsense_version = version_utils.get_opnsense_version()

        # set module
        _module_name = "password"

        # get php_requirements
        try:
            version_map: dict = module_index.VERSION_MAP[_opnsense_version]
        except KeyError as ke:
            raise UnsupportedOPNsenseVersion(
                f"OPNsense version '{_opnsense_version}' not supported "
                "by puzzle.opnsense collection.\n"
                f"Supported versions are {list(module_index.VERSION_MAP.keys())}"
            ) from ke

        if _module_name not in version_map:
            raise UnsupportedVersionForModule(
                f"Module '{_module_name}' not supported "
                f"for OPNsense version '{_opnsense_version}'.\n"
                f"Supported modules are {list(version_map.keys())}"
            )

        _config_map = version_map[_module_name]
        php_requirements = _config_map["php_requirements"]
        configure_function = _config_map["configure_functions"]["name"]
        configure_params = _config_map["configure_functions"]["configure_params"]

        formatted_params = [
            param.replace("'password'", f"'{password}'") if "password" in param else param
            for param in configure_params
        ]

        return opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function=configure_function,
            configure_params=formatted_params,
        ).get("stdout")

    # pylint: disable=too-many-locals
    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "User":
        """ """

        disabled = params.get("disabled")
        username = params.get("username")
        password = params.get("password")

        if password:
            password = cls._set_password(password)

        uid = params.get("uid")
        description = params.get("description")
        scope = params.get("scope")
        ipsecpsk = params.get("ipsecpsk")
        otp_seed = params.get("otp_seed")
        shell = params.get("shell")
        full_name = params.get("full_name")
        email = params.get("email")
        comment = params.get("comment")
        landing_page = params.get("landing_page")
        expires = params.get("expires")
        authorizedkeys = params.get("authorizedkeys")
        cert = params.get("cert")
        api_keys_item_api_key = params.get("api_keys_item_api_key")

        user_dict = {
            "disabled": disabled,
            "name": username,
            "password": password,
            "descr": description,
            "scope": scope,
            "ipsecpsk": ipsecpsk,
            "otp_seed": otp_seed,
            "shell": shell,
            "uid": uid,
            "full_name": full_name,
            "email": email,
            "comment": comment,
            "landing_page": landing_page,
            "expires": expires,
            "authorizedkeys": authorizedkeys,
            "cert": cert,
            "api_keys_item_api_key": api_keys_item_api_key,
        }

        user_dict = {key: value for key, value in user_dict.items() if value is not None}

        return cls(**user_dict)

    @staticmethod
    def from_xml(element: Element) -> "User":
        """ """

        user_dict: dict = xml_utils.etree_to_dict(element)["user"]

        return User(**user_dict)


class UserSet(OPNsenseModuleConfig):
    """ """

    _users: List[User]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(module_name="users", path=path)
        self._users = self._load_users()

    def _load_users(self) -> List[User]:
        element_tree_users: Element = self.get("system")

        element_tree_users.findall("user")

        user_list = []
        for user in element_tree_users:
            if user.tag == "user":
                user_list.append(user)

        return [User.from_xml(user_data) for user_data in user_list]

    @property
    def changed(self) -> bool:
        """ """

        return self._load_users() != self._users

    def add_or_update(self, user: User) -> None:
        """
        Adds or updates a user in the user list.

        This method checks for the existence of the provided `user` in the user list.
        If found, the user's details are updated. If not, the user is added. Existence is
        determined by the `User` class's equality condition.

        For new users without a UID, the method assigns the next available UID and updates
        the UID counter.

        Parameters:
            user (User): The user to add or update.

        Returns:
            None.
        """

        existing_user: Optional[User] = next((r for r in self._users if r == user), None)
        next_uid: Element = self.get("uid")

        if existing_user:
            existing_user.__dict__.update(user.__dict__)
        else:
            if not user.uid:
                user.uid = next_uid.text

                # increase the next_uid
                self.set(value=str(int(next_uid.text) + 1), setting="uid")

            self._users.append(user)

    def delete(self, user: User) -> None:
        """ """

        self._users = [r for r in self._users if r != user]

    def find(self, **kwargs) -> Optional[User]:
        """ """

        for user in self.__users:
            match = all(getattr(user, key, None) == value for key, value in kwargs.items())
            if match:
                return user
        return None

    def save(self) -> bool:
        """ """

        if not self.changed:
            return False

        filter_element: Element = self._config_xml_tree.find(self._config_map["system"])

        # Iterate over the filter_element and remove each user element
        for user_element in filter_element.findall("user"):
            if user_element.tag == "user":
                # TODO: compare the diffrent attributes

                filter_element.remove(user_element)

        # Extend the filter_element with the updated user elements
        filter_element.extend([user.to_etree() for user in self._users])

        tree: ElementTree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)
        self._config_xml_tree = self._load_config()

        return True
