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
    User,
    UserSet,
    Group,
    OPNsenseCryptReturnError,
    OPNsenseGroupNotFoundError,
    OPNsenseHashVerifyReturnError,
    hash_verify,
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
                <user_dn>uid=test_user_1,ou=users,dc=example,dc=com</user_dn>
                <descr>test_user_1</descr>
                <expires />
                <authorizedkeys />
                <apikeys>
                    <item>
                        <key>AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy</key>
                        <secret>$6$$f8zJvXeCng1iaUCaq8KLvg4tJbGQ.qWKmfgcpytflpGF4AXc4U.N8/TiczM6fu741KBB2PwWUC0k7fzet8asq0</secret>
                    </item>
                </apikeys>vagrantvagrant
                <ipsecpsk />
                <otp_seed />
                <shell>/bin/sh</shell>
                <uid>1001</uid>
            </user>
            <user>
                <name>test_user_23</name>
                <password>$2y$11$FGohY592rylJdDw5vTaxNubYHwh9326Eb7gtdY4GRbXrViGsPEykq</password>
                <scope>User</scope>
                <descr>[ ANSIBLE ]</descr>
                <ipsecpsk/>
                <otp_seed/>
                <shell>/bin/sh</shell>
                <uid>2021</uid>
                <full_name>[ ANSIBLE ]</full_name>
                <expires/>
                <authorizedkeys/>
                <groupname>test_group</groupname>
            </user>
            <group>
                <name>admins</name>
                <description>System Administrators</description>
                <scope>system</scope>
                <gid>1999</gid>
                <member>0</member>
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
                <member>2004</member>
                <member>2021</member>
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
    assert test_user.shell == "/bin/sh"
    assert test_user.uid == "1000"
    assert not hasattr(test_user, "api_keys")


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


# attribute apikeys tests
def test_user_with_api_key_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_user: Element = list(list(test_etree_opnsense))[0][3]
    test_user: User = User.from_xml(test_etree_user)

    assert test_user.name == "test_user_1"
    assert (
        test_user.password
        == "$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O"
    )
    assert test_user.scope == "user"
    assert test_user.descr == "test_user_1"
    assert (
        test_user.apikeys[0]["secret"]
        == "$6$$f8zJvXeCng1iaUCaq8KLvg4tJbGQ.qWKmfgcpytflpGF4AXc4U.N8/TiczM6fu741KBB2PwWUC0k7fzet8asq0"
    )
    assert (
        test_user.apikeys[0]["key"]
        == "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert test_user.expires is None
    assert test_user.authorizedkeys is None
    assert test_user.ipsecpsk is None
    assert test_user.otp_seed is None
    assert test_user.shell == "/bin/sh"
    assert test_user.uid == "1001"


# Function user_from_ansible_params attributes Unit-Tests


def test_user_from_ansible_module_params_simple(sample_config_path):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "disabled": True,
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
    }
    new_test_user: User = User.from_ansible_module_params(test_params)
    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.disabled == 1
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.authorizedkeys is None
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


def test_new_user_from_ansible_module_params_required(sample_config_path):
    test_params: dict = {
        "username": "not_existing_user",
        "password": "vagrant",
    }
    new_test_user: User = User.from_ansible_module_params(test_params)
    assert new_test_user.name == "not_existing_user"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.expires is None
    assert new_test_user.authorizedkeys is None
    assert new_test_user.ipsecpsk is None


def test_new_user_from_ansible_module_params_additional_parameters(sample_config_path):
    test_params: dict = {
        "username": "not_existing_user",
        "password": "vagrant",
        "full_name": "new not_existing_user",
        "email": "test@test.com",
        "comment": "this is a test",
        "landing_page": "/test.html",
        "shell": "/bin/sh",
        "expires": "11/17/2024",
    }
    new_test_user: User = User.from_ansible_module_params(test_params)
    assert new_test_user.name == "not_existing_user"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "new not_existing_user"
    assert new_test_user.email == "test@test.com"
    assert new_test_user.comment == "this is a test"
    assert new_test_user.landing_page == "/test.html"
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.expires == "11/17/2024"
    assert new_test_user.authorizedkeys is None
    assert new_test_user.ipsecpsk is None


def test_group_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)
    test_etree_group: Element = list(list(test_etree_opnsense)[0])[5]
    test_group: Group = Group.from_xml(test_etree_group)
    assert test_group.name == "admins"
    assert test_group.description == "System Administrators"
    assert test_group.scope == "system"
    assert test_group.member == [
        "0",
        "2004",
        "2005",
        "2006",
        "2009",
        "2010",
        "2014",
    ]
    assert test_group.gid == "1999"


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
    assert new_test_user.shell == "/bin/sh"
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
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_group_as_string(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
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
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_multiple_groups_as_list(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
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
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_no_groups(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
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
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_with_not_existing_group(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
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
        with pytest.raises(OPNsenseGroupNotFoundError) as excinfo:
            test_user = User.from_ansible_module_params(test_params)
            user_set.add_or_update(test_user)
            user_set.save()
        assert "Group 'not_existing_group' not found on Instance" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_single_group_removal(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
):
    test_params = {
        "username": "test_user_23",
        "password": "test_password_23",
        "scope": "user",
        "full_name": "[ ANSIBLE ]",
        "shell": "/bin/sh",
        "uid": "2021",
        "groups": [],
    }
    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)
        user_set.add_or_update(test_user)
        assert user_set.changed
        user_set.save()
    with UserSet(sample_config_path) as new_user_set:
        all_groups = new_user_set._load_groups()
        test_user: User = user_set.find(name="test_user_23")
        test_group = all_groups[1]
        assert "2021" not in test_group.member
        assert not test_user.groupname
        new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_single_group_removal_no_param(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
):
    test_params = {
        "username": "test_user_23",
        "password": "test_password_23",
        "scope": "user",
        "full_name": "[ ANSIBLE ]",
        "shell": "/bin/sh",
        "uid": "2021",
    }
    with UserSet(sample_config_path) as user_set:
        test_user = User.from_ansible_module_params(test_params)
        assert not hasattr(test_user, "groupname")
        # assert len(test_user.groupname) == 0
        user_set.add_or_update(test_user)
        assert user_set.changed
        user_set.save()
    # with UserSet(sample_config_path) as new_user_set:
    #     all_groups = new_user_set._load_groups()
    #     test_user: User = user_set.find(name="test_user_23")
    #     test_group = all_groups[1]
    #     assert "2021" in test_group.member
    #     assert test_user.groupname
    #     new_user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_from_ansible_module_params_multiple_group_removal(
    mock_set_password,
    mock_get_version,
    mock_password_verify: MagicMock,
    sample_config_path,
):
    test_params = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "groups": [],
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


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_new_user_from_ansible_module_params_with_multiple_api_keys(
    mock_set_password: MagicMock,
    mock_get_version: MagicMock,
    mock_password_verify: MagicMock,
    mock_run_function: MagicMock,
    sample_config_path,
):
    test_params: dict = {
        "username": "test_user_2",
        "password": "test_password_2",
        "scope": "user",
        "full_name": "test_user_2",
        "shell": "/bin/sh",
        "uid": "1000",
        "apikeys": [
            {
                "key": "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy",
                "secret": "O6OQc0uNZ1w/ihSAVGyPbPzXmBhOt1hUpytSMU2NGdQfQWYlSDFtwY4xAquJtJLPQS0cN6conp59QGf5+icYvQ==",
            },
            {
                "key": "BMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy",
                "secret": "lvU6lbOscmeunpWVHFfDlj4yF4DVp7uXOuH3770BkH0Tf4w4XFB/GKJw6+RzJPtoauKkHoPz/1y0NT0SRn3vqQ==",
            },
        ],
    }

    mock_run_function.return_value = {
        "stdout": "$6$somerandomsalt$hashedsecretvalue1234567890123456789012345678901234567890123456789054583",
        "stderr": None,
    }

    with UserSet(sample_config_path) as user_set:
        new_test_user: User = User.from_ansible_module_params(test_params)
        user_set.add_or_update(new_test_user)
        user_set.save()

    assert new_test_user.name == "test_user_2"
    assert new_test_user.password == "test_password_2"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "test_user_2"
    assert new_test_user.expires is None
    assert len(new_test_user.apikeys) == 2
    assert (
        new_test_user.apikeys[0]["key"]
        == "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert (
        new_test_user.apikeys[0]["secret"]
        == "O6OQc0uNZ1w/ihSAVGyPbPzXmBhOt1hUpytSMU2NGdQfQWYlSDFtwY4xAquJtJLPQS0cN6conp59QGf5+icYvQ=="
    )
    assert (
        new_test_user.apikeys[1]["key"]
        == "BMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert (
        new_test_user.apikeys[1]["secret"]
        == "lvU6lbOscmeunpWVHFfDlj4yF4DVp7uXOuH3770BkH0Tf4w4XFB/GKJw6+RzJPtoauKkHoPz/1y0NT0SRn3vqQ=="
    )
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.User.encode_authorizedkeys",
    return_value="3J35EY37QTNXFFEECJGZ32WVYQC5W4GZ",
)
def test_existing_user_from_ansible_module_params_with_multiple_api_keys(
    mock_set_encode_authorizedkeys, mock_set_password, sample_config_path
):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "apikeys": [
            {
                "key": "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy",
                "secret": "O6OQc0uNZ1w/ihSAVGyPbPzXmBhOt1hUpytSMU2NGdQfQWYlSDFtwY4xAquJtJLPQS0cN6conp59QGf5+icYvQ==",
            },
            {
                "key": "BMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy",
                "secret": "lvU6lbOscmeunpWVHFfDlj4yF4DVp7uXOuH3770BkH0Tf4w4XFB/GKJw6+RzJPtoauKkHoPz/1y0NT0SRn3vqQ==",
            },
        ],
    }
    new_test_user: User = User.from_ansible_module_params(test_params)
    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert len(new_test_user.apikeys) == 2
    assert (
        new_test_user.apikeys[0]["key"]
        == "AMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert (
        new_test_user.apikeys[0]["secret"]
        == "O6OQc0uNZ1w/ihSAVGyPbPzXmBhOt1hUpytSMU2NGdQfQWYlSDFtwY4xAquJtJLPQS0cN6conp59QGf5+icYvQ=="
    )
    assert (
        new_test_user.apikeys[1]["key"]
        == "BMC39xLYvfD7PyaemZrIVuaWBIdRQVS9NgEHFWzW7+xj0ExFY+07/Vz6HcmUVkJkjb8N0Cg7yEdESvNy"
    )
    assert (
        new_test_user.apikeys[1]["secret"]
        == "lvU6lbOscmeunpWVHFfDlj4yF4DVp7uXOuH3770BkH0Tf4w4XFB/GKJw6+RzJPtoauKkHoPz/1y0NT0SRn3vqQ=="
    )
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_user_set_load_simple_user(
    mocked_version_utils: MagicMock, mock_password_verify: MagicMock, sample_config_path
):
    with UserSet(sample_config_path) as user_set:
        assert len(user_set._users) == 3
        user_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
def test_user_from_ansible_module_params_with_provided_otp_seed(
    mock_set_password, sample_config_path
):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "otp_seed": "some_seed",
    }
    new_test_user: User = User.from_ansible_module_params(test_params)
    assert new_test_user.name == "vagrant"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.otp_seed == "some_seed"
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
def test_user_from_ansible_module_params_with_generated_otp_seed(
    mock_set_password, sample_config_path
):
    test_params: dict = {
        "username": "new_user",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "/bin/sh",
        "uid": "1000",
        "otp_seed": "",
    }

    new_test_user: User = User.from_ansible_module_params(test_params)

    assert new_test_user.name == "new_user"
    assert new_test_user.password == "vagrant"
    assert new_test_user.scope == "user"
    assert new_test_user.descr == "vagrant box management"
    assert new_test_user.expires is None
    assert new_test_user.otp_seed is None
    assert new_test_user.ipsecpsk is None
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.User.encode_authorizedkeys",
    return_value="3J35EY37QTNXFFEECJGZ32WVYQC5W4GZ",
)
def test_user_from_ansible_module_params_with_authorizedkeys(
    mock_set_encode_authorizedkeys, mock_set_password, sample_config_path
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
    assert new_test_user.shell == "/bin/sh"
    assert new_test_user.uid == "1000"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
def test_generate_hashed_secret_success(mock_run_function):
    mock_run_function.return_value = {
        "stdout": "$6$somerandomsalt$hashedsecretvalue1234567890123456789012345678901234567890123456789054583",
        "stderr": None,
    }
    user = User(name="test", password="test")
    result = user.generate_hashed_secret("password123")
    assert (
        result
        == "$6$somerandomsalt$hashedsecretvalue1234567890123456789012345678901234567890123456789054583"
    )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
def test_generate_hashed_secret_failure_invalid_hash(mock_run_function):
    mock_run_function.return_value = {
        "stdout": "$5$somerandomsalt$shortvalue",
        "stderr": None,
    }
    user = User(name="test", password="test")
    with pytest.raises(OPNsenseCryptReturnError) as excinfo:
        user.generate_hashed_secret("password123")
    assert "validation of the secret failed!" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
def test_generate_hashed_secret_error_in_crypt(mock_run_function):
    mock_run_function.return_value = {"stdout": "", "stderr": "error in crypt function"}
    user = User(name="test", password="test")
    with pytest.raises(OPNsenseCryptReturnError) as excinfo:
        user.generate_hashed_secret("password123")
    assert "error encounterd while creating secret" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command"
)
def test_password_verify_returns_true_on_match(mock_run_command: MagicMock):
    # Mock the return value of the run_command to simulate a password match
    mock_run_command.return_value = {
        "stdout": "bool(true)",
        "stderr": None,
    }
    # Call the function with test data
    test_password_matches = hash_verify(
        plain_string="test_password_1",
        existing_hashed_string="$2y$11$pSYTZcD0o23JSfksEekwKOnWM1o3Ih9vp7OOQN.v35E1rag49cEc6",
    )
    # Assert that the function returns True for a password match
    assert test_password_matches


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command"
)
def test_password_verify_returns_false_on_difference(mock_run_command: MagicMock):
    # Mock the return value of the run_command to simulate a password match
    mock_run_command.return_value = {
        "stdout": "1",
        "stderr": None,
    }
    # Call the function with test data
    test_password_matches = hash_verify(
        plain_string="test_password_1",
        existing_hashed_string="$2y$11$pSYTZcD0o23JSfksEe1231345h9vp7OOQN.v35E1rag49cEc6",
    )
    # Assert that the function returns True for a password match
    assert not test_password_matches


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_command"
)
def test_password_verify_returns_OPNsenseHashVerifyReturnError(
    mock_run_command: MagicMock,
):
    # Mock the return value of the run_command to simulate a password match
    mock_run_command.return_value = {
        "stdout": None,
        "stderr": "this an error",
    }
    with pytest.raises(OPNsenseHashVerifyReturnError) as excinfo:
        # Call the function with test data
        test_password_matches = hash_verify(
            plain_string="test_password_1",
            existing_hashed_string="$2y$11$pSYTZcD0o23JSfksEekwKOnWM1o3Ih9vp7OOQN.v35E1rag49cEc6",
        )
    assert "error encounterd verifying hash" in str(excinfo.value)


def test_user_with_empty_paramters_to_etree():
    test_user: User = User(
        password="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
        scope="user",
        name="vagrant",
        descr="vagrant box management",
        shell="",
        email="",
        uid="1000",
    )

    test_element = test_user.to_etree()

    assert not hasattr(test_element, "shell")
    assert not hasattr(test_element, "email")


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.User.encode_authorizedkeys",
    return_value="3J35EY37QTNXFFEECJGZ32WVYQC5W4GZ",
)
def test_user_from_ansible_module_params_with_empty_parameters(
    mock_set_encode_authorizedkeys, mock_set_password, sample_config_path
):
    test_params: dict = {
        "username": "vagrant",
        "password": "vagrant",
        "scope": "user",
        "full_name": "vagrant box management",
        "shell": "",
        "email": "",
        "uid": "1000",
        "authorizedkeys": "test_authorizedkey",
    }
    new_test_user: User = User.from_ansible_module_params(test_params)

    assert not hasattr(new_test_user, "shell")
    assert not hasattr(new_test_user, "email")


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.opnsense_utils.run_function"
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.UserSet.set_user_password",
    return_value="$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.system_access_users_utils.hash_verify",
    return_value=True,
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_new_user_from_ansible_module_params_with_empty_parameters(
    mock_set_password: MagicMock,
    mock_get_version: MagicMock,
    mock_password_verify: MagicMock,
    mock_run_function: MagicMock,
    sample_config_path,
):
    test_params: dict = {
        "username": "test_user_2",
        "password": "test_password_2",
        "scope": "user",
        "full_name": "test_user_2",
        "shell": "",
        "uid": "1000",
        "email": "",
    }

    mock_run_function.return_value = {
        "stdout": "$6$somerandomsalt$hashedsecretvalue1234567890123456789012345678901234567890123456789054583",
        "stderr": None,
    }

    with UserSet(sample_config_path) as user_set:
        new_test_user: User = User.from_ansible_module_params(test_params)
        user_set.add_or_update(new_test_user)
        user_set.save()

    assert not hasattr(new_test_user, "shell")
    assert not hasattr(new_test_user, "email")
