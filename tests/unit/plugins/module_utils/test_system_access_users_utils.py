# Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: skip-file
import os
from tempfile import NamedTemporaryFile
from unittest.mock import patch, MagicMock
from xml.etree import ElementTree
from xml.etree.ElementTree import Element


import pytest

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils import (
    Group,
    User,
    UserSet,
    UserLoginShell,
    OPNSenseGroupNotFoundError,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "password": {
            "php_requirements": [
                "/usr/local/etc/inc/auth.inc",
            ],
            "configure_functions": {
                "name": "echo password_hash",
                "configure_params": [
                    "'password'",
                    "PASSWORD_BCRYPT",
                    "[ 'cost' => 11 ]",
                ],
            },
        },
    }
}

TEST_XML: str = """<?xml version="1.0"?>
    <opnsense>
        <system>
            <hostname>test_name</hostname>
            <test>test_name_2</test>
            <user>
                <password>$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O</password>
                <scope>user</scope>
                <name>vagrant</name>
                <descr>vagrant box management</descr>
                <expires />
                <authorizedkeys />
                <ipsecpsk />
                <otp_seed />
                <shell>/bin/sh</shell>
                <uid>1000</uid>
            </user>
            <user>
                <password>$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O</password>
                <scope>user</scope>
                <name>test_user_1</name>
                <descr>test_user_1</descr>
                <expires />
                <authorizedkeys />
                <apikeys>
                    <item>
                        <key>AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy</key>
                        <secret>$6$$f8zJvXeCng1iaUCaq8KLvg4tJbGQ.qWKmfgcpytflpGF4AXc4U.N8/TiczM6fu741KBB2PwWUC0k7fzet8asq0</secret>
                    </item>
                </apikeys>
                <ipsecpsk />
                <otp_seed />
                <shell>/bin/sh</shell>
                <uid>1001</uid>
            </user>
            <group>
                <name>admins</name>
                <description>System Administrators</description>
                <scope>system</scope>
                <gid>1999</gid>
                <member>0</member>
                <member>1000</member>
                <member>2004</member>
                <member>2005</member>
                <member>2006</member>
                <member>2009</member>
                <member>2010</member>
                <member>2014</member>
                <priv>page-all</priv>
            </group>
            <group>
                <name>test_group</name>
                <description>test_group</description>
                <scope>system</scope>
                <member>1000</member>
                <member>2004</member>
                <gid>2000</gid>
                <priv>page-all</priv>
            </group>
        </system>
    </opnsense>
    """


@pytest.fixture(scope="function")
def sample_config_path(request):
    """
    Fixture that creates a temporary file with a test XML configuration.
    The file  is used in the tests.

    Returns:
    - str: The path to the temporary file.
    """
    with patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",  # pylint: disable=line-too-long
        return_value="OPNsense Test",
    ), patch.dict(VERSION_MAP, TEST_VERSION_MAP, clear=True):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


def test_user_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_user: Element = list(list(test_etree_opnsense)[0])[2]
    test_user: User = User.from_xml(test_etree_user)

    assert test_user.name == "vagrant"
    assert (
        test_user.password
        == "$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O"
    )
    assert test_user.scope == "user"
    assert test_user.descr == "vagrant box management"
    assert test_user.expires is None
    assert test_user.authorizedkeys is None
    assert test_user.ipsecpsk is None
    assert test_user.otp_seed is None
    assert test_user.shell == UserLoginShell.SH
    assert test_user.uid == "1000"


def test_user_to_etree():
    test_user: User = User(
        password="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
        scope="user",
        name="vagrant",
        descr="vagrant box management",
        shell="/bin/sh",
        uid="1000",
    )

    test_element = test_user.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_user: Element = list(list(orig_etree)[0])[2]

    assert xml_utils.elements_equal(test_element, orig_user)


def test_user_with_api_key_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_user: Element = list(list(test_etree_opnsense)[0])[3]
    test_user: User = User.from_xml(test_etree_user)

    assert test_user.name == "test_user_1"
    assert (
        test_user.password
        == "$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O"
    )
    assert test_user.scope == "user"
    assert test_user.descr == "test_user_1"
    assert (
        test_user.apikeys["item"]["secret"]
        == "$6$$f8zJvXeCng1iaUCaq8KLvg4tJbGQ.qWKmfgcpytflpGF4AXc4U.N8/TiczM6fu741KBB2PwWUC0k7fzet8asq0"
    )
    assert (
        test_user.apikeys["item"]["key"]
        == "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert test_user.expires is None
    assert test_user.authorizedkeys is None
    assert test_user.ipsecpsk is None
    assert test_user.otp_seed is None
    assert test_user.shell == UserLoginShell.SH
    assert test_user.uid == "1001"


def test_user_to_etree():
    test_user: User = User(
        password="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
        scope="user",
        name="vagrant",
        descr="vagrant box management",
        shell="/bin/sh",
        uid="1000",
    )

    test_element = test_user.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_user: Element = list(list(orig_etree)[0])[2]

    assert xml_utils.elements_equal(test_element, orig_user)


def test_user_from_ansible_module_params_simple(sample_config_path):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }

    new_test_user: User = User.from_ansible_module_params(test_params)

    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.authorizedkeys is None
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == UserLoginShell.SH
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_set_load_simple_user(mocked_version_utils: MagicMock, sample_config_path):
    with UserSet(sample_config_path) as user_set:
        assert len(user_set._users) == 2
        user_set.save()


def test_group_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_group: Element = list(list(test_etree_opnsense)[0])[4]
    test_group: Group = Group.from_xml(test_etree_group)

    assert test_group.name == "admins"
    assert test_group.description == "System Administrators"
    assert test_group.scope == "system"
    assert test_group.member == [
        "0",
        "1000",
        "2004",
        "2005",
        "2006",
        "2009",
        "2010",
        "2014",
    ]
    assert test_group.gid == "1999"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_set_add_group(
    mocked_version_utils: MagicMock, mock_set_password: MagicMock, sample_config_path
):
    with UserSet(sample_config_path) as user_set:
        test_user: User = user_set.find(name="vagrant")
        test_user.groupname = ["admins"]

        user_set.add_or_update(test_user)

        assert user_set.changed

        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        new_test_user: User = new_user_set.find(name="vagrant")
        # group: Group = new_user_set

        assert new_test_user.groupname == ["admins"]
        assert "1000" in new_user_set._groups[0].member

        new_user_set.save()


def test_user_from_ansible_module_params_with_group(sample_config_path):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "groups": ["admins"],
    }

    new_test_user: User = User.from_ansible_module_params(test_params)

    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.authorizedkeys is None
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == UserLoginShell.SH
    assert new_test_user.uid == "1000"
    assert new_test_user.groupname == ["admins"]


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_group_as_string(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "test",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "groups": ["test_group"],
    }

    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)

        user_set.add_or_update(test_user)

        assert user_set.changed
        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        new_test_user = new_user_set.find(name="test")

        # Adjust the assertions based on the actual implementation of your User and UserSet classes

        assert "test_group" in new_test_user.groupname

        new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_multiple_groups_as_list(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "test",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "groups": ["admins", "test_group"],
    }

    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)

        user_set.add_or_update(test_user)

        assert user_set.changed
        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        new_test_user = new_user_set.find(name="test")

        # Adjust the assertions based on the actual implementation of your User and UserSet classes

        assert (
            "admins" in new_test_user.groupname
            and "test_group" in new_test_user.groupname
        )

        new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_no_groups(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "test",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }

    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)

        user_set.add_or_update(test_user)

        assert user_set.changed
        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        new_test_user = new_user_set.find(name="test")

        assert new_test_user.name == "test"

        new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_not_existing_group(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "test",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "groups": ["not_existing_group"],
    }

    with UserSet(sample_config_path) as user_set:
        with pytest.raises(OPNSenseGroupNotFoundError) as excinfo:
            test_user = User.from_ansible_module_params(test_params)

            user_set.add_or_update(test_user)

            user_set.save()

        assert "Group 'not_existing_group' not found on Instance" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.User.set_authorizedkeys",
    return_value="3J35EY37QTNXFFEECJGZ32WVYQC5W4GZ",
)
def test_user_from_ansible_module_params_with_authorizedkeys(
    mock_set_set_authorizedkeys, mock_set_password, sample_config_path
):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "authorizedkeys": "test_authorizedkey",
    }

    new_test_user: User = User.from_ansible_module_params(test_params)

    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.authorizedkeys == "3J35EY37QTNXFFEECJGZ32WVYQC5W4GZ"
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == UserLoginShell.SH
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_single_group_removal(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }

    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)

        user_set.add_or_update(test_user)

        assert user_set.changed
        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        all_groups = new_user_set._load_groups()

        admin_group = all_groups[0]

        assert "1000" not in admin_group.member

        new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_multiple_group_removal(
    mock_set_password, mock_get_version, sample_config_path
):
    test_params = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }

    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)

        user_set.add_or_update(test_user)

        assert user_set.changed
        user_set.save()

    with UserSet(sample_config_path) as new_user_set:
        all_groups = new_user_set._load_groups()

        admin_group = all_groups[0]
        test_group = all_groups[1]

        assert "1000" not in admin_group.member
        assert "1000" not in test_group.member

        new_user_set.save()
