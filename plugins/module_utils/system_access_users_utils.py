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


from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
import base64
import os
import binascii

from xml.etree.ElementTree import Element, ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)

from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


class OPNSenseCryptReturnError(Exception):
    """
    Exception raised when the return value of the instance is not what is expected
    """


class OPNSenseGroupNotFoundError(Exception):
    """
    Exception raised when an OPNsense group is not found.
    """


class OPNSenseHashVerifyReturnError(Exception):
    """
    Exception raised when the return value of the instance is not what is expected
    """


class OPNSenseNotValidBase64APIKeyError(Exception):
    """
    Exception raised when a not valid base32 api code is provided
    """


def hash_verify(existing_hashed_string: str, plain_string: Optional[str]) -> bool:
    """
    Verifies if a plain string matches an existing hashed string.

    Args:
        existing_hashed_string (str): The existing hashed string to verify against.
        plain_string (Optional[str]): The plain string to verify.

    Returns:
        bool: True if the plain string matches the hashed string, otherwise False.

    Raises:
        OPNSenseHashVerifyReturnError: If an error occurs during hash verification.
    """

    if plain_string is None:
        return False

    # escape plain_string
    escaped_string = plain_string.replace("\\", "\\\\").replace("'", "\\'")

    # check if current plain_string matches hash
    hash_matches = opnsense_utils.run_command(
        php_requirements=[],
        command=f"var_dump(password_verify('{escaped_string}','{existing_hashed_string}'));",
    )

    if hash_matches.get("stderr"):
        raise OPNSenseHashVerifyReturnError(
            f"error encounterd verifying hash {hash_matches.get('stderr')}"
        )

    # if return code of hash_matches is true, it's a match
    if hash_matches.get("stdout") == "bool(true)":
        return True

    return False


def apikeys_verify(existing_apikeys: List[Dict], apikeys: List[Dict]) -> bool:
    """
    Verifies if a list of API keys matches existing API keys.

    Args:
        existing_apikeys (List[Dict]): List of existing API keys with 'key' and hashed 'secret'.
        apikeys (List[Dict]): List of new API keys with 'key' and plain 'secret'.

    Returns:
        bool: True if all new API keys match the existing ones, otherwise False.
    """

    if apikeys is None:
        return False

    # if the List[Dict] matches, return True
    if apikeys == existing_apikeys:
        return True

    existing_keys_and_secrets = {
        apikey["key"]: apikey["secret"] for apikey in existing_apikeys
    }

    for apikey in apikeys:
        key = apikey["key"]
        plain_secret = apikey["secret"]

        if key not in existing_keys_and_secrets:
            # Key does not exist
            return False

        if not hash_verify(existing_keys_and_secrets[key], plain_secret):
            # Secret does not match
            return False

    # If all keys and secrets match
    return True


@dataclass
class Group:
    """
    Represents a Group entity with various attributes.

    Args:
        name (str): The name of the group.
        description (str): A description of the group.
        scope (Optional[str]): The scope of the group, if specified.
        priv (Optional[str]): Privileges associated with the group, if applicable.
        gid (Optional[str]): The group's unique identifier, if provided.
        member (Optional[List[str]]): List of member usernames in the group, if any.

    Methods:
        from_xml(element: Element): Creates a Group instance from an XML Element.
        to_etree(self): Converts the Group instance to an XML Element.
        remove_user(self): Removes a user from the group.
        check_if_user_in_group(self, user: "User"): Checks if a user is already in the group.
        add_user(self, user: "User"): Adds a user to the group.

    The Group class is designed to represent group entities with various attributes commonly used
    in system configurations. It provides methods for creating from XML, converting to XML,
    checking if a user is in the group, and adding/removing a user to/from the group.
    """

    name: str
    description: str
    scope: Optional[str] = None
    priv: Optional[str] = None
    gid: Optional[str] = None
    member: Optional[List[str]] = None

    @staticmethod
    def from_xml(element: Element) -> "Group":
        """Creates a Group instance from an XML Element."""

        group_dict: dict = xml_utils.etree_to_dict(element)["group"]

        if "member" in group_dict and isinstance(group_dict["member"], str):
            group_dict["member"] = [group_dict["member"]]

        return Group(**group_dict)

    def to_etree(self) -> Element:
        """Converts the Group instance to an XML Element."""

        group_dict: dict = asdict(self)

        element: Element = xml_utils.dict_to_etree("group", group_dict)[0]

        return element

    def check_if_user_in_group(self, user: "User") -> bool:
        """
        Checks if a user is already in the group.

        Args:
            user (User): The User object to check if they are in the group.

        Returns:
            bool: True if the user is in the group, False otherwise.
        """

        if self.member and user.uid in self.member:
            return True

        return False

    def add_user(self, user: "User") -> None:
        """
        Adds a user to the group.

        Args:
            user (User): The User object to add to the group.

        This function adds a user to the group by appending their UID to the group's member list.
        """

        if not isinstance(self.member, list):
            self.member = [self.member] if self.member else []

        self.member.append(user.uid)

    def remove_user(self, user: "User") -> None:
        """
        Removes a user from the group.

        Args:
            user (User): The User object to remove from the group.

        This function removes a user from the group by removing their UID
        from the group's member list.
        """

        if not isinstance(self.member, list):
            # Convert self.member to a list if it's not already a list.
            # If self.member is None or empty, this will set it to an empty list.
            self.member = [self.member] if self.member else []

        # Check if the user's UID is in the member list, then remove it.
        if user.uid in self.member:
            self.member.remove(user.uid)


class User:
    """
    A class representing a user with various attributes and functionalities.

    Methods:
        __init__(**kwargs):
            Initializes a User object with given attributes.

        __eq__(other):
            Compares two User objects for equality.

        generate_hashed_secret(secret: str) -> str:
            Generates a hashed secret using the crypt function.

        _apikeys_from_xml(apikeys: dict) -> List[Dict]:
            Converts API keys from an XML format to a list of dictionaries.

        from_xml(element: Element) -> "User":
            Converts an XML element into a User object.

        generate_apikeys(apikeys: List[dict] = None) -> List[dict]:
            Generates API keys, encoding them as necessary.

        set_otp_seed(otp_seed: str = None) -> str:
            Sets or generates an OTP seed.

        encode_authorizedkeys(authorizedkeys: Optional[str] = None) -> Optional[str]:
            Encodes authorized SSH keys as base64.

        to_etree() -> Element:
            Converts the User object to an XML element.

        from_ansible_module_params(cls, params: dict) -> "User":
            Creates a User instance from Ansible module parameters.
    """

    @staticmethod
    def generate_hashed_secret(secret: str) -> str:
        """Generates a hashed secret using the crypt function."""

        # load requirements
        php_requirements = []
        configure_function = "echo crypt"
        configure_params = [f"'{secret}'", "'$6$'"]

        # set user password
        hashed_secret_value = opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function=configure_function,
            configure_params=configure_params,
        )

        # check if stderr returns value
        if hashed_secret_value.get("stderr"):
            raise OPNSenseCryptReturnError("error encounterd while creating secret")

        # validate secret
        if (
            hashed_secret_value.get("stdout").startswith("$6$")
            and len(hashed_secret_value.get("stdout")) >= 90
        ):
            return hashed_secret_value.get("stdout")

        # if validation fails,
        raise OPNSenseCryptReturnError(
            f"""
            validation of the secret failed!
            Secret must start with $6$ and have a min length of 90
            Value: {hashed_secret_value}
            """
        )

    def __init__(self, **kwargs):

        # set default attributes
        self.authorizedkeys = kwargs.get("authorizedkeys", None)
        self.disabled = kwargs.get("disabled", False)
        self.expires = kwargs.get("expires", None)
        self.ipsecpsk = kwargs.get("ipsecpsk", None)
        self.otp_seed = kwargs.get("otp_seed", None)

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __eq__(self, other) -> bool:

        if not isinstance(other, User):
            return False

        if self.__dict__.get("password") and other.__dict__.get("password"):

            if not self.__dict__["password"] == other.__dict__["password"]:
                if not hash_verify(
                    existing_hashed_string=self.__dict__["password"],
                    plain_string=other.__dict__["password"],
                ):
                    return False

        if self.__dict__.get("apikeys") and other.__dict__.get("apikeys"):
            if not apikeys_verify(
                existing_apikeys=self.__dict__["apikeys"],
                apikeys=other.__dict__["apikeys"],
            ):
                return False

        self_dict = {
            k: v for k, v in self.__dict__.items() if k not in ["apikeys", "password"]
        }
        other_dict = {
            k: v for k, v in other.__dict__.items() if k not in ["apikeys", "password"]
        }

        return self_dict == other_dict

    @staticmethod
    def _apikeys_from_xml(apikeys: dict) -> List[Dict]:
        if isinstance(apikeys, str):
            return [{}]

        api_keys = []
        if isinstance(apikeys, list):
            for pair in apikeys:
                item = pair.get("item", {})
                api_keys.append({"key": item.get("key"), "secret": item.get("secret")})
        elif apikeys.get("item"):
            item = apikeys.get("item", {})
            api_keys.append({"key": item.get("key"), "secret": item.get("secret")})

        return api_keys

    @staticmethod
    def from_xml(element: Element) -> "User":
        """
        Converts an XML element into a User object.

        Parameters:
            element (Element): An XML element representing a user, with child elements
            for each user attribute.

        Returns:
            User: A User object initialized with the data extracted from the XML element.

        This method extracts data from an XML element, handling different data types appropriately,
        such as converting single group names into a list and interpreting the
        'disabled' field as a boolean.
        """

        user_dict: dict = xml_utils.etree_to_dict(element)["user"]

        if "groupname" in user_dict and user_dict["groupname"] is None:
            user_dict["groupname"] = []

        if "groupname" in user_dict and isinstance(user_dict["groupname"], str):
            user_dict["groupname"] = [user_dict["groupname"]]

        # Handle 'disabled' element
        user_dict["disabled"] = user_dict.get("disabled", "0") == "1"

        # handle apikeys element
        if user_dict.get("apikeys"):
            user_dict["apikeys"] = User._apikeys_from_xml(user_dict.get("apikeys"))

        return User(**user_dict)

    @staticmethod
    def generate_apikeys(apikeys: List[dict] = None) -> List[dict]:
        """Generates or validates API keys."""

        api_keys: List[dict] = []

        for apikey in apikeys:
            # Check if key and secret are provided
            if not apikey["key"]:
                key = base64.b64encode(os.urandom(60)).decode("utf-8")

                if not apikey["secret"]:
                    secret = base64.b64encode(os.urandom(60)).decode("utf-8")

                api_keys.append({"key": key, "secret": secret})
            else:
                try:
                    base64.b64decode(apikey["key"])
                    base64.b64decode(apikey["secret"])

                    api_keys.append(apikey)

                except binascii.Error as binascii_error_message:
                    raise OPNSenseNotValidBase64APIKeyError(
                        f"The API key: {apikey} is not a valid base64 string. "
                        f"Error: {str(binascii_error_message)}"
                    ) from binascii_error_message

        return api_keys

    @staticmethod
    def set_otp_seed(otp_seed: str = None) -> str:
        """Sets or generates an OTP seed."""

        if otp_seed is None or otp_seed == "":
            return base64.b32encode(os.urandom(20).encode("utf-8")).decode("utf-8")

        return otp_seed

    @staticmethod
    def encode_authorizedkeys(authorizedkeys: Optional[str] = None) -> Optional[str]:
        """
        Encodes the authorized SSH keys as base32.

        Args:
            authorizedkeys (str, optional): SSH keys to encode (default: None).

        Returns:
            str: Base32-encoded authorized SSH keys.

        Encodes the provided SSH keys as base32. If no keys are provided,
        an empty string is returned.
        """

        if authorizedkeys:
            return base64.b64encode(authorizedkeys.encode("utf-8")).decode("utf-8")

        return None

    def to_etree(self) -> Element:
        """Converts the User object into an XML element."""
        user_dict: dict = self.__dict__.copy()

        for user_key, user_val in list(user_dict.items()):
            if user_val is None and user_key in [
                "expires",
                "ipsecpsk",
                "otp_seed",
                "authorizedkeys",
            ]:
                continue

            if isinstance(user_val, list) and user_key == "apikeys":
                user_dict[user_key] = [
                    {
                        "item": {
                            key_name: (
                                User.generate_hashed_secret(secret_value)
                                if key_name == "secret"
                                and not secret_value.startswith("$6$")
                                else secret_value
                            )
                            for key_name, secret_value in api_key_dict.items()
                        }
                    }
                    for api_key_dict in user_val
                ]

            elif user_val is None or user_val is False:
                del user_dict[user_key]
                continue

            elif isinstance(user_val, bool):
                user_dict[user_key] = "1"

        element: Element = xml_utils.dict_to_etree("user", user_dict)[0]

        return element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "User":
        """
        Creates a User instance from Ansible module parameters.

        Args:
            params (dict): Parameters from an Ansible module, expected to contain
                        user attributes such as 'username', 'password', etc.

        Returns:
            User: An instance of the User class initialized with the provided parameters.
                Fields not provided are omitted from initialization.

        This method processes parameters typically received from an Ansible module,
        handling optional attributes and setting the password securely if provided.
        """

        user_dict = {
            "disabled": params.get("disabled"),
            "name": params.get("username"),
            "password": params.get("password"),
            "descr": params.get("full_name"),
            "scope": params.get("scope"),
            "ipsecpsk": params.get("ipsecpsk"),
            "otp_seed": (
                User.set_otp_seed(otp_seed=params.get("otp_seed"))
                if params.get("otp_seed") is not None and params.get("otp_seed") != ""
                else None
            ),
            "shell": params.get("shell"),
            "uid": params.get("uid"),
            "full_name": params.get("full_name"),
            "email": params.get("email"),
            "comment": params.get("comment"),
            "landing_page": params.get("landing_page"),
            "expires": params.get("expires"),
            "groupname": params.get("groups") if params.get("groups") else [],
            "authorizedkeys": User.encode_authorizedkeys(
                authorizedkeys=params.get("authorizedkeys", None)
            ),
            "cert": params.get("cert"),
            "apikeys": (
                User.generate_apikeys(apikeys=params.get("apikeys"))
                if params.get("apikeys")
                else None
            ),
        }

        user_dict = {
            key: value for key, value in user_dict.items() if value is not None
        }

        return cls(**user_dict)


class UserSet(OPNsenseModuleConfig):
    """
    Represents a collection of user and group configurations within the OPNsense system,
    facilitating the management of users and groups through direct manipulation of the system's
    configuration file.

    The UserSet class provides a high-level interface to add, update, delete, and find users and
    groups in the system's configuration, abstracting the complexities of direct XML manipulation.
    It ensures that changes to users and groups are consistent and coherent, maintaining the
    integrity of the system's access control and configuration.

    Upon initialization, the class loads existing user and group configurations from the specified
    configuration file path, allowing for subsequent operations to reflect the current state of the
    system accurately. The class offers methods to perform CRUD (Create, Read, Update, Delete)
    operations on user and group entities, alongside utility methods to check for changes and save
    updates back to the configuration file.

    Attributes:
        _users (List[User]): A list of User objects representing the users currently managed by
                             the system.
        _groups (List[Group]): A list of Group objects representing the groups currently managed
                               by the system.

    Methods:
        __init__(self, path: str): Initializes a new UserSet instance, loading users and groups
                                   from the specified configuration file.
        _load_users(self): Loads users from the system configuration into the _users list.
        _load_groups(self): Loads groups from the system configuration into the _groups list.
        add_or_update(self, user: User): Adds a new user or updates an existing one in the system.
        delete(self, user: User): Removes a specified user from the system's configuration.
        find(self, **kwargs): Searches for and returns a user matching specified criteria.
        save(self): Saves changes made to users or groups back to the system's configuration file.

    Usage:
        The UserSet class is intended for use within the OPNsense system's configuration management
        tools, providing a structured and safe approach to modifying user and group settings.

    Note:
        Modifications made through UserSet instances are not persisted automatically. The `save`
        method must be called to write changes back to the configuration file.
    """

    _users: List[User]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="system_access_users",
            config_context_names=["system_access_users", "password"],
            path=path,
        )
        self._users = self._load_users()
        self._groups = self._load_groups()
        self._config_xml_tree = self._load_config()

    def _load_users(self) -> List[User]:
        """
        Loads user data from the system's configuration and converts it into a list of User objects.

        This method accesses the 'system' element of the configuration, searching for all 'user'
        elements. Each found 'user' element represents a user configuration within the system.
        The method collects these elements, and for each one, it creates a User object by parsing
        the XML data into the structured format defined by the User data class.

        The conversion process relies on the `from_xml` class method of the User, which interprets
        the XML data and initializes a User object with the corresponding attributes extracted from
        the XML element.

        Returns:
            List[User]: A list of User objects representing all users found in the system's
                        configuration. If no users are found, an empty list is returned.

        Note:
            This method is intended to be used internally within the class to refresh or initialize
            the in-memory representation of users based on the current state of the system's
            configuration.
        """

        element_tree_users: Element = self.get("system")

        element_tree_users.findall("user")

        user_list = []
        for user in element_tree_users:
            if user.tag == "user":
                user_list.append(user)

        return [User.from_xml(user_data) for user_data in user_list]

    def _load_groups(self) -> List:
        """
        Loads and returns a list of Group objects from the system's configuration XML.

        This method parses the system's configuration file to extract information about groups,
        creating a list of Group objects. Each group found within the 'system' configuration
        section is instantiated as a Group object based on its XML representation.

        Returns:
            List[Group]: A list of Group objects representing all groups found in the system's
                        configuration file. The groups are extracted by searching for 'group'
                        tags within the 'system' section of the configuration XML.

        The process involves searching the XML for all 'group' elements, collecting these elements
        into a list, and then transforming each XML element into a Group object using the static
        method `Group.from_xml`. This method is critical for initializing the internal state of
        the system with the current group configurations as defined in the configuration file.

        Note:
            The method assumes that the 'system' element of the configuration XML is already loaded
            and accessible via the `self.get("system")` call, which should return the relevant
            XML section for parsing.
        """

        element_tree_groups: Element = self.get("system")

        element_tree_groups.findall("group")

        group_list = []
        for group in element_tree_groups:
            if group.tag == "group":
                group_list.append(group)

        return [Group.from_xml(group_data) for group_data in group_list]

    @property
    def changed(self) -> bool:
        """
        Evaluates whether there have been changes to user or group configurations that are not yet
        reflected in the saved system configuration. This property serves as a check to determine
        if updates have been made in memory to the user or group lists that differ from what is
        currently persisted in the system's configuration files.

        Returns:
            bool: True if there are changes to the user or group configurations that have not been
                persisted yet; False otherwise.

        The method works by comparing the current in-memory representations of users and groups
        against the versions loaded from the system's configuration files. A difference in these
        lists indicates that changes have been made in the session that have not been saved, thus
        prompting the need for a save operation to update the system configuration accordingly.

        Note:
            This property should be consulted before performing a save operation to avoid
            unnecessary writes to the system configuration when no changes have been made.
        """
        return self._load_users() != self._users or self._load_groups() != self._groups

    def set_user_password(self, user: User) -> None:
        """
        Sets the user's password using specified PHP and configuration functions.
        """

        # load requirements
        php_requirements = self._config_maps["password"]["php_requirements"]

        # load requirements
        configure_function_dict = self._config_maps["password"]["configure_functions"]
        configure_function_key = next(
            (key for key in configure_function_dict if key != "name"), None
        )
        configure_function = configure_function_dict[configure_function_key]["name"]
        configure_params = configure_function_dict[configure_function_key][
            "configure_params"
        ]

        # sanitize and escape password
        escaped_password = user.password.replace("\\", "\\\\").replace("'", "\\'")

        # format parameters
        formatted_params = [
            (
                param.replace("'password'", f"'{escaped_password}'")
                if "password" in param
                else param
            )
            for param in configure_params
        ]

        # set user password
        user.password = opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function=configure_function,
            configure_params=formatted_params,
        ).get("stdout")

        # since "password" is no longer needed, it can be popped
        self._config_maps.pop("password")

    @staticmethod
    def set_api_keys_secret(user: User) -> None:
        """
        Sets the API keys for a user, hashing the 'secret' key if not already hashed.

        Args:
            user (User): The user object containing API keys to be processed.

        Returns:
            None

        The function iterates over the user's API keys and hashes the 'secret' key using
        User.generate_hashed_secret if the key name is 'secret' and the value does not already start
        with "$6$". Other keys and values are left unchanged.
        """

        user.apikeys = [
            {
                key_name: (
                    User.generate_hashed_secret(secret_value)
                    if key_name == "secret" and not secret_value.startswith("$6$")
                    else secret_value
                )
                for key_name, secret_value in api_key_dict.items()
            }
            for api_key_dict in user.apikeys
        ]

    def _update_user_groups(self, user: User, existing_user: Optional[User] = None):
        """
        Manages the association of a user with specified groups, either by updating the groups of an
        existing user or adding a new user to the appropriate groups. This method ensures that the
        user is a member of all specified groups, adding the user to any groups they are not already
        a part of, and maintains the integrity of group memberships across updates.
        If user.groupname is None, the user is removed from all groups.

        Parameters:
            user (User): The user whose group memberships are to be updated. This includes both new
                        users and users whose group memberships might change.
            existing_user (Optional[User]): If the user already exists, this parameter should be the
                                            user's current information. It is used to determine if
                                            the existing group memberships need to be updated.

        Raises:
            OPNSenseGroupNotFoundError: If a specified group does not exist on the instance, this
                                        exception is raised, indicating the need for corrective
                                        action or error handling.
        """
        target_user = existing_user if existing_user else user

        if len(user.groupname) == 0 or not hasattr(user, "groupname"):
            for existing_group in self._groups:
                if existing_group.check_if_user_in_group(target_user):
                    existing_group.remove_user(target_user)

                    if target_user.__dict__.get("groupname"):
                        target_user.groupname.remove(existing_group.name)
                        if not target_user.groupname:
                            target_user.groupname = []

            return  # Exit the method after removing the user from all groups.

        # Convert groupname to a list if it's not already.
        group_names = (
            user.groupname if isinstance(user.groupname, list) else [user.groupname]
        )

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
                raise OPNSenseGroupNotFoundError(
                    f"Group '{group_name}' not found on Instance"
                )

    def add_or_update(self, user: User) -> None:
        """
        Adds a new user to the system or updates an existing user's information, ensuring that group
        associations are correctly managed. This method determines whether the provided user already
        exists within the system. If the user exists, it updates the user's details and group
        associations; if the user does not exist, it assigns a unique user ID and adds the user to
        the system.

        The method handles the assignment of user IDs and updates the internal tracking of the next
        available ID. It also manages group memberships by updating group associations for both new
        and existing users as necessary.

        Parameters:
            user (User): The user object to add or update. This object should contain all relevant
                        information about the user, including username, password, and any group
                        memberships.

        Note:
            This operation directly affects the internal list of users managed by this instance,
            reflecting changes immediately in the system's state. However, persistent storage or
            external system updates must be handled separately to ensure that changes remain
            effective across sessions or reboots.

        Returns:
            None: This method does not return a value but updates the internal state to include or
                modify the specified user's information.
        """

        existing_user: Optional[User] = next(
            (u for u in self._users if u.name == user.name), None
        )
        next_uid: Element = self.get("uid")

        if existing_user:
            if not hash_verify(
                existing_hashed_string=existing_user.password,
                plain_string=user.password,
            ):
                self.set_user_password(user)
            else:
                user.__dict__.pop("password")

            if hasattr(user, "apikeys"):
                if not apikeys_verify(
                    existing_apikeys=existing_user.apikeys, apikeys=user.apikeys
                ):
                    self.set_api_keys_secret(user)

            # Update groups if needed
            self._update_user_groups(user, existing_user)

            # Update existing user's attributes
            existing_user.__dict__.update(user.__dict__)

            return

        self.set_user_password(user)

        # Assign UID if not set
        if not hasattr(user, "uid"):
            user.uid = next_uid.text
            # Increase the next_uid
            self.set(value=str(int(next_uid.text) + 1), setting="uid")

        if hasattr(user, "groupname"):
            # Update groups for the new user
            self._update_user_groups(user)

        # Add the new user
        self._users.append(user)

    def delete(self, user: User) -> None:
        """
        Removes a specified user from the internal list of managed users.

        This method filters out the specified user from the current list of users managed by this
        instance. It iterates over the list of users and retains only those that do not match the
        user to be deleted. This approach ensures that the specified user is effectively removed
        from the list, reflecting the deletion operation.

        It's important to note that this operation directly modifies the internal state of the
        instance by updating the list of users to exclude the specified user. However, this method
        does not handle the persistence of these changes to any external storage or configuration
        files. Any required persistence mechanism should be handled separately, ensuring that the
        deletion has the intended effect across sessions or system states.

        Parameters:
            user (User): The user object to be removed from the list of managed users.

        Returns:
            None: This method does not return a value but updates the internal list of users.
        """

        self._users = [r for r in self._users if r != user]

    def find(self, **kwargs) -> Optional[User]:
        """
        Searches for a user matching specified criteria within the stored user list.

        This method iterates over the collection of users managed by the instance, evaluating each
        user against the provided keyword arguments. The comparison is performed by ensuring all
        specified attributes of a user match the corresponding values given in `kwargs`.

        The method employs a flexible approach, allowing for the search of users based on any number
        of attributes, such as name, group, or any other user-specific detail that is available as
        an attribute of the User objects.

        If a user meeting all the specified criteria is found, that User object is returned. If no
        matching user is found after checking all users in the collection, the method returns None,
        indicating the absence of a user with the specified attributes.

        Parameters:
            **kwargs: Variable keyword arguments representing the attributes and their expected
                      values for the user to match.

        Returns:
            Optional[User]: The User object that matches the criteria, or None if no match is found.
        """

        for user in self._users:
            match = all(
                getattr(user, key, None) == value for key, value in kwargs.items()
            )
            if match:
                return user
        return None

    def save(self) -> bool:
        """
        Saves updated configuration to the XML file if changes are detected.

        Initially checks for modifications via the `changed` attribute. If unchanged, it returns
        False, indicating no save operation was necessary. For changes, the XML configuration tree
        is updated accordingly.

        Retrieves the 'system' element using `_config_map`, removing old 'user' and 'group' elements
        to clear outdated configurations. It then repopulates 'system' with updated configurations
        for users and groups, converting each to an XML element via `to_etree()` method.

        After updating, it writes the changes to the file system with UTF-8 encoding and XML
        declaration. Subsequently, the configuration file is reloaded to update the internal state
        with the new changes.

        Concludes by returning True to indicate successful change persistence.

        Returns:
            bool: True if changes were successfully saved, False if no changes occurred.
        """

        if not self.changed:
            return False

        # Assuming self._config_maps["system_access_users"]["system"]
        # gives you the path to the 'system' element
        filter_element: Element = self._config_xml_tree.find(
            self._config_maps["system_access_users"]["system"]
        )

        # Remove specific child elements (e.g., 'user', 'group') from filter_element
        for user_element in list(
            filter_element.findall("user")
        ):  # Use list() to avoid modification during iteration
            filter_element.remove(user_element)

        for group_element in list(filter_element.findall("group")):
            filter_element.remove(group_element)

        # Now, add the updated elements back directly to filter_element
        filter_element.extend([group.to_etree() for group in self._groups])
        filter_element.extend([user.to_etree() for user in self._users])

        # Write the updated XML tree to the file
        tree: ElementTree = ElementTree(self._config_xml_tree)

        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        # Reload the configuration to reflect the updated changes
        self._config_xml_tree = self._load_config()

        return True
