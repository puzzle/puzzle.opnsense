# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the plugins.module_utils.xml_utils module."""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils


@pytest.mark.parametrize("input_dict", [
    {"test": 1},
    {"test": "some_string"},
    {"test": None}
])
def test_dict_to_etree__simple_dict_with_value(input_dict: dict) -> None:
    """
    Given a simple input dictionary, check that the xml tag takes the dict key
    value and the xml inner text is set as the dict value. E.g.:
    Given: {"test":1}
    Expected XML: <test>1</test>
    """
    output_etree: Element = xml_utils.dict_to_etree(input_dict)

    assert output_etree.tag == list(input_dict.keys())[0]
    assert output_etree.text == input_dict[list(input_dict.keys())[0]]


def test_dict_to_etree__enforce_single_root_dict() -> None:
    """
    Given a simple input dictionary, check that the xml tag takes the dict key
    value and the xml inner text is set as the dict value. E.g.:
    Given: {"test":1}
    Expected XML: <test>1</test>
    """
    input_dict: dict = {"test_1": 1, "test_2": 2}
    with pytest.raises(xml_utils.XMLUtilsUnsupportedInputFormatError):
        output_etree: Element = xml_utils.dict_to_etree(input_dict)
