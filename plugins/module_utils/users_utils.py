#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from dataclasses import dataclass, asdict, fields, field
from enum import Enum
from typing import List, Optional

from xml.etree.ElementTree import Element, ElementTree, SubElement

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

from ansible_collections.puzzle.opnsense.plugins.module_utils.xml_utils import etree_to_dict


class OPNSenseGroupNotFoundError(Exception):
    """
    Exception raised when an OPNsense group is not found.
    """


class ListEnum(Enum):
    """Enum class with some handy utility functions."""

    @classmethod
    def as_list(cls) -> List[str]:
        """
        Return a list
        Returns
        -------

        """
        return [entry.value for entry in cls]

    @classmethod
    def from_string(cls, value: str) -> "ListEnum":
        """
        Returns Enum value, from a given String.
        If no enum value can be mapped to the input string,
        ValueError is raised.
        Parameters
        ----------
        value: `str`
            String to be mapped to enum value

        Returns
        -------
        Enum value
        """
        for _key, _value in cls.__members__.items():
            if value in (_key, _value.value):
                return _value
        raise ValueError(f"'{cls.__name__}' enum not found for '{value}'")


class UserLoginShell(ListEnum):
    """Represents the user login shell."""

    NOLOGIN = "/sbin/nologin"
    CSH = "/bin/csh"
    SH = "/bin/sh"
    TCSH = "/bin/tcsh"


@dataclass
class Group:
    """Used to represent a Group."""

    name: str
    description: str
    scope: Optional[str] = None
    priv: Optional[str] = None
    gid: Optional[str] = None
    member: List[str] = field(default_factory=list)

    @staticmethod
    def from_xml(element: Element) -> "Group":
        """ """

        group_dict: dict = xml_utils.etree_to_dict(element)["group"]

        # Handle 'disabled' element
        # user_dict["disabled"] = user_dict.get("disabled", "0") == "1"

        return Group(**group_dict)

    def to_etree(self) -> Element:
        """ """

        group_dict: dict = asdict(self)

        element: Element = xml_utils.dict_to_etree("group", group_dict)[0]

        return element

    def check_if_user_in_group(self, user: "User") -> bool:
        """
        This function checks, if a user is already in the group
        """

        if self.member and user.uid in self.member:
            return True

        return False

    def add_user(self, user: "User") -> None:
        """
        This function adds a user to a group
        """

        if not isinstance(self.member, list):
            self.member = [self.member] if self.member else []

        self.member.append(user.uid)


@dataclass
class User:
    """Used to represent an User."""

    name: str
    password: str
    scope: Optional[str] = "User"
    descr: Optional[str] = None
    ipsecpsk: Optional[str] = None
    otp_seed: Optional[str] = None
    shell: Optional[UserLoginShell] = None
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
    groupname: Optional[list[str]] = None

    def __eq__(self, other) -> bool:
        if not isinstance(other, User):
            return False

        for field in fields(self):
            if field.name != "password" and field.name != "uid":
                if getattr(self, field.name) != getattr(other, field.name):
                    return False

        return True

    def __post_init__(self):
        # Manually define the fields and their expected types
        enum_fields = {
            "shell": UserLoginShell,
        }

        for field_name, field_type in enum_fields.items():
            value = getattr(self, field_name)

            # Check if the value is a string and the field_type is a subclass of ListEnum
            if isinstance(value, str) and issubclass(field_type, ListEnum):
                # Convert string to ListEnum
                setattr(self, field_name, field_type.from_string(value))

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

            if issubclass(type(user_val), ListEnum):
                user_dict[user_key] = user_val.value

            elif user_val is None or user_val is False:
                del user_dict[user_key]
                continue

            elif isinstance(user_val, bool):
                user_dict[user_key] = "1"

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
        scope = params.get("scope")
        ipsecpsk = params.get("ipsecpsk")
        otp_seed = params.get("otp_seed")
        shell = params.get("shell")
        full_name = params.get("full_name")
        email = params.get("email")
        comment = params.get("comment")
        landing_page = params.get("landing_page")
        expires = params.get("expires")
        groupname = params.get("groups")
        authorizedkeys = params.get("authorizedkeys")
        cert = params.get("cert")
        api_keys_item_api_key = params.get("api_keys_item_api_key")

        user_dict = {
            "disabled": disabled,
            "name": username,
            "password": password,
            "descr": full_name,
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
            "groupname": groupname,
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

        # Handle 'disabled' element
        user_dict["disabled"] = user_dict.get("disabled", "0") == "1"

        return User(**user_dict)


class UserSet(OPNsenseModuleConfig):
    """ """

    _users: List[User]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(module_name="users", path=path)
        self._users = self._load_users()
        self._groups = self._load_groups()

    def _load_users(self) -> List[User]:
        element_tree_users: Element = self.get("system")

        element_tree_users.findall("user")

        user_list = []
        for user in element_tree_users:
            if user.tag == "user":
                user_list.append(user)

        return [User.from_xml(user_data) for user_data in user_list]

    def _load_groups(self) -> List:
        element_tree_groups: Element = self.get("system")

        element_tree_groups.findall("group")

        group_list = []
        for group in element_tree_groups:
            if group.tag == "group":
                group_list.append(group)

        return [Group.from_xml(group_data) for group_data in group_list]

    @property
    def changed(self) -> bool:
        """ """

        return self._load_users() != self._users and self._load_groups() != self._groups

    def _update_user_groups(self, user: User, existing_user: Optional[User] = None):
        """
        Updates or adds the user to specified groups.

        Parameters:
        - user: The user to be added or updated in groups.
        - existing_user: The existing user object, if the user already exists.
        """

        target_user = existing_user if existing_user else user
        group_names = user.groupname if isinstance(user.groupname, list) else [user.groupname]

        for group_name in group_names:
            group_found = False
            for index, existing_group in enumerate(self._groups):
                if existing_group.name == group_name:
                    group_found = True
                    if not existing_group.check_if_user_in_group(target_user):
                        existing_group.add_user(target_user)
                        self._groups[index] = existing_group
                    break  # Stop searching once the group is found

            if not group_found:
                # Group was not found, raise an exception
                raise OPNSenseGroupNotFoundError(f"Group '{group_name}' not found on Instance")

    def add_or_update(self, user: User) -> None:
        """
        Adds a new user or updates an existing one, including group associations.

        Parameters:
        - user: The user to add or update.
        """
        existing_user: Optional[User] = next((r for r in self._users if r == user), None)
        next_uid: Element = self.get("uid")

        if existing_user:
            # Update groups if needed
            self._update_user_groups(user, existing_user)
            # Update existing user's attributes
            existing_user.__dict__.update(user.__dict__)
        else:
            # Assign UID if not set
            if not user.uid:
                user.uid = next_uid.text
                # Increase the next_uid
                self.set(value=str(int(next_uid.text) + 1), setting="uid")

            # Update groups for the new user
            self._update_user_groups(user)
            # Add the new user
            self._users.append(user)

    def delete(self, user: User) -> None:
        """ """

        self._users = [r for r in self._users if r != user]

    def find(self, **kwargs) -> Optional[User]:
        """ """

        for user in self._users:
            match = all(getattr(user, key, None) == value for key, value in kwargs.items())
            if match:
                return user
        return None

    def save(self) -> bool:
        """ """

        if not self.changed:
            return False

        # Assuming self._config_map["system"] gives you the path to the 'system' element
        filter_element: Element = self._config_xml_tree.find(self._config_map["system"])

        # Remove specific child elements (e.g., 'user', 'group') from filter_element
        for user_element in list(
            filter_element.findall("user")
        ):  # Use list() to avoid modification during iteration
            filter_element.remove(user_element)

        for group_element in list(filter_element.findall("group")):
            filter_element.remove(group_element)

        ## Now, add the updated elements back directly to filter_element
        filter_element.extend([group.to_etree() for group in self._groups])
        filter_element.extend([user.to_etree() for user in self._users])

        # Write the updated XML tree to the file
        tree: ElementTree = ElementTree(self._config_xml_tree)

        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        # Reload the configuration to reflect the updated changes
        self._config_xml_tree = self._load_config()

        return True
