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
                </apikeys>
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


def test_user_kwargs_plain_password():
    """
    Unit test to ensure, that a plain password can be set
    """

    test_user: User = User(plain_password="test_password")

    assert test_user.plain_password
    assert test_user.plain_password == "test_password"


def test_user_from_xml():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_user: Element = list(list(test_etree_opnsense)[0])[2]
    test_user: User = User.from_xml(test_etree_user)

    assert test_user.name == "vagrant"
    assert test_user.password == "$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O"
    assert test_user.scope == "user"
    assert test_user.descr == "vagrant box management"
    assert test_user.expires is None
    assert test_user.authorizedkeys is None
    assert test_user.ipsecpsk is None
    assert test_user.otp_seed is None
    assert test_user.shell == "/bin/sh"
    assert test_user.uid == "1000"
    assert not hasattr(test_user, "api_keys")
    assert not hasattr(test_user, "plain_password")


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
