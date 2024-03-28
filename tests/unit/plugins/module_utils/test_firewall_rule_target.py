#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from ansible_collections.puzzle.opnsense.plugins.module_utils.firewall_rules_utils import FirewallRuleTarget


def test_from_ansible_module_params_correct_default_return():
    """
    Test the build class method FirewallRuleTarget.source_from_ansible_params
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

    source_target: FirewallRuleTarget = FirewallRuleTarget.source_from_ansible_params(test_params)
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

    source_target: FirewallRuleTarget = FirewallRuleTarget.source_from_ansible_params(test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address == "192.168.0.1/24"
    assert source_target.port == "any"
    assert not source_target.any
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

    source_target: FirewallRuleTarget = FirewallRuleTarget.source_from_ansible_params(test_params)
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

    source_target: FirewallRuleTarget = FirewallRuleTarget.source_from_ansible_params(test_params)
    assert isinstance(source_target, FirewallRuleTarget)
    assert source_target.address is None
    assert source_target.port == "22"
    assert source_target.any
    assert not source_target.invert
