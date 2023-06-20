# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the plugins.module_utils.xml_utils module."""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from typing import Union, Optional
from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils


@pytest.mark.parametrize("input_data", [
    1,
    "foo",
    None
])
def test_dict_to_etree__primitive_values(input_data: Optional[Union[int, str]]) -> None:
    """
    Given a simple input dictionary, check that the xml tag takes the dict key
    value and the xml inner text is set as the dict value. E.g.:
    Given: {"test":1}
    Expected XML: <test>1</test>
    """
    test_tag: str = "test"
    output_etree: list[Element] = xml_utils.dict_to_etree(test_tag, input_data)

    assert len(output_etree) == 1
    assert output_etree[0].tag == test_tag
    assert output_etree[0].text == input_data


@pytest.mark.parametrize("input_data", [
    {"foo": 1},
    {"foo": "bar"},
    {"foo": 1, "bar": None},
])
def test_dict_to_etree__simple_dicts(input_data: dict) -> None:
    """
    Given a simple input dictionary, check that the xml tag takes the dict key
    value and the xml inner text is set as the dict value. E.g.:
    Given: {"test":1}
    Expected XML: <test>1</test>
    """
    test_tag: str = "test"
    output_etree: list[Element] = xml_utils.dict_to_etree(test_tag, input_data)
    output_children: list[Element] = list(output_etree[0])
    assert len(output_etree) == 1
    assert output_etree[0].tag == test_tag
    assert output_etree[0].text is None
    assert len(output_children) == len(input_data)
    for out_child in output_children:
        assert out_child.tag in list(input_data.keys())
