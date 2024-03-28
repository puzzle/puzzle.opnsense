#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_rules_utils import FirewallRuleTarget


def test_from_ansible_module_params_correct_default_return():
    """
    Test the build class method FirewallRuleTarget.from_ansible_params
    when default module params are given.
    :return:
    """
    # These are the default ansible module params as specified
    # in the module DOCUMENTATION
    test_params: dict = {
        "source_ip": "any",
        "source_port": "any",
        "source_invert": False,
    }

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_ansible_params("source",test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address is None
    assert source_target.port == "any"
    assert source_target.any
    assert not source_target.invert


def test_from_ansible_module_params_set_ip():
    """
    Given an IP in the source param 'source_ip' it is expected
    to be assigned to the FirewallRuleTarget.address instance attribute.
    :return:
    """
    test_params: dict = {
        "source_ip": "192.168.0.1/24",
        "source_port": "any",
        "source_invert": False,
    }

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_ansible_params("source",test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address == "192.168.0.1/24"
    assert source_target.port == "any"
    assert not source_target.any
    assert not source_target.invert

def test_from_ansible_module_params_set_port():
    """
    Given an IP in the source param 'source_ip' it is expected
    to be assigned to the FirewallRuleTarget.address instance attribute.
    :return:
    """
    test_params: dict = {
        "source_ip": "any",
        "source_port": "8000-9000",
        "source_invert": False,
    }

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_ansible_params("source",test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address is None
    assert source_target.port == "8000-9000"
    assert source_target.any
    assert not source_target.invert


def test_from_ansible_module_params_set_invert():
    """
    Given an inverted input ("source_invert" == True), the FirewallRuleTarget.invert
    attribute must be 'True' as well.
    :return:
    """
    test_params: dict = {
        "source_ip": "any",
        "source_port": "any",
        "source_invert": True,
    }

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_ansible_params("source",test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address is None
    assert source_target.port == "any"
    assert source_target.any
    assert source_target.invert


def test_from_ansible_module_params_set_port():
    """
    Given a port input ("source_port" == "22"), the FirewallRuleTarget.port
    attribute must be '22' as well.
    :return:
    """
    test_params: dict = {
        "source_ip": "any",
        "source_port": "22",
        "source_invert": False,
    }

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_ansible_params("source",test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address is None
    assert source_target.port == "22"
    assert source_target.any
    assert not source_target.invert


def test_from_xml_basic_source():
    basic_source_xml: str = """
    <source>
        <any/>
    </source>
    """
    test_etree_source: Element = ElementTree.fromstring(basic_source_xml)

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_xml("source", test_etree_source)

    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.any
    assert source_target.address is None
    assert source_target.port is "any"
    assert not source_target.invert


def test_from_xml_test_not():
    basic_source_xml: str = """
    <source>
        <not/>
    </source>
    """
    test_etree_source: Element = ElementTree.fromstring(basic_source_xml)

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_xml("source", test_etree_source)

    assert isinstance(source_target, FirewallRuleTarget)
    assert not source_target.any
    assert source_target.address is None
    assert source_target.port is "any"
    assert source_target.invert


def test_from_xml_test_address():
    basic_source_xml: str = """
    <source>
        <address>10.0.0.1/24</address>
    </source>
    """
    test_etree_source: Element = ElementTree.fromstring(basic_source_xml)

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_xml("source", test_etree_source)

    assert isinstance(source_target, FirewallRuleTarget)
    assert not source_target.any
    assert source_target.address == "10.0.0.1/24"
    assert source_target.port is "any"
    assert not source_target.invert


def test_from_xml_test_port():
    basic_source_xml: str = """
    <source>
        <port>22</port>
    </source>
    """
    test_etree_source: Element = ElementTree.fromstring(basic_source_xml)

    source_target: FirewallRuleTarget = FirewallRuleTarget.from_xml("source", test_etree_source)

    assert isinstance(source_target, FirewallRuleTarget)
    assert not source_target.any
    assert source_target.address is None
    assert source_target.port == "22"
    assert not source_target.invert
