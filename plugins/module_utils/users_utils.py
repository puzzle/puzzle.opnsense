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
    member: Optional[List[str]] = None

    @staticmethod
    def from_xml(element: Element) -> "Group":
        """ """

        group_dict: dict = xml_utils.etree_to_dict(element)["group"]

        if "member" in group_dict and isinstance(group_dict["member"], str):
            group_dict["member"] = [group_dict["member"]]

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
        """
        Converts an XML element into a User object.

        Parameters:
            element (Element): An XML element representing a user, with child elements for each user attribute.

        Returns:
            User: A User object initialized with the data extracted from the XML element.

        This method extracts data from an XML element, handling different data types appropriately,
        such as converting single group names into a list and interpreting the 'disabled' field as a boolean.
        """

        user_dict: dict = xml_utils.etree_to_dict(element)["user"]

        if "groupname" in user_dict and isinstance(user_dict["groupname"], str):
            user_dict["groupname"] = [user_dict["groupname"]]

        # Handle 'disabled' element
        user_dict["disabled"] = user_dict.get("disabled", "0") == "1"

        return User(**user_dict)


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
        super().__init__(module_name="users", path=path)
        self._users = self._load_users()
        self._groups = self._load_groups()

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
            This property should be consulted before performing a save operation to avoid unnecessary
            writes to the system configuration when no changes have been made.
        """

        return self._load_users() != self._users or self._load_groups() != self._groups

    def _update_user_groups(self, user: User, existing_user: Optional[User] = None):
        """
        Manages the association of a user with specified groups, either by updating the groups of an
        existing user or adding a new user to the appropriate groups. This method ensures that the
        user is a member of all specified groups, adding the user to any groups they are not already
        a part of, and maintains the integrity of group memberships across updates.

        Parameters:
            user (User): The user whose group memberships are to be updated. This includes both new
                        users and users whose group memberships might change.
            existing_user (Optional[User]): If the user already exists, this parameter should be the
                                            user's current information. It is used to determine if
                                            the existing group memberships need to be updated.

        The method iterates through the groups specified for the user, checking whether each group
        exists and whether the user is already a member. If a group does not exist, an exception is
        raised to indicate the issue. If the user is not already a member of a group, they are added.

        Note:
            This method can raise an OPNSenseGroupNotFoundError if any of the specified groups do
            not exist on the instance, ensuring that the caller can handle such cases appropriately.

        Raises:
            OPNSenseGroupNotFoundError: If a specified group does not exist on the instance, this
                                        exception is raised, indicating the need for corrective
                                        action or error handling.

        This approach ensures that user-group associations are accurately reflected and maintained
        within the system, supporting consistent access control and group-based configurations.
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

        existing_user: Optional[User] = next((r for r in self._users if r == user), None)
        next_uid: Element = self.get("uid")

        if existing_user:
            # Update groups if needed
            if existing_user.groupname:
                self._update_user_groups(user, existing_user)
            # Update existing user's attributes
            existing_user.__dict__.update(user.__dict__)
        else:
            # Assign UID if not set
            if not user.uid:
                user.uid = next_uid.text
                # Increase the next_uid
                self.set(value=str(int(next_uid.text) + 1), setting="uid")

            if user.groupname:
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
            match = all(getattr(user, key, None) == value for key, value in kwargs.items())
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
