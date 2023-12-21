# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for the plugins.module_utils.xml_utils module."""

# This is probably intentional and required for the fixture
# pylint: disable=redefined-outer-name

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import xml.etree.ElementTree as ET
from typing import Union, Optional, List
from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils


###############################
# --- Dict to ElementTree --- #
###############################


@pytest.mark.parametrize("input_data", [1, "foo", None])
def test_dict_to_etree__primitive_values(input_data: Optional[Union[int, str]]) -> None:
    """
    Test converting a primitive value to an ElementTree.Element.

    Given a primitive input value, the function should create an ElementTree.Element
    with the given tag and set the text content of the element to the input value.

    For example:
    - Input: tag: foo, dict: 1
    - Expected XML: <foo>1</foo>
    """
    test_tag: str = "test"
    output_etree: List[Element] = xml_utils.dict_to_etree(test_tag, input_data)

    assert len(output_etree) == 1
    assert output_etree[0].tag == test_tag
    assert output_etree[0].text == input_data


@pytest.mark.parametrize(
    "input_data",
    [
        {"foo": 1},
        {"foo": "bar"},
        {"foo": 1, "bar": None},
    ],
)
def test_dict_to_etree__tags_on_simple_dicts(input_data: dict) -> None:
    """
    Test converting a simple dictionary to an ElementTree.Element.

    Given a simple input dictionary, the function should create an ElementTree.Element with the
    given tag and add child elements for each key-value pair in the dictionary.

    For example:
    - Input: tag: foo, dict: {"test": 1}
    - Expected XML: <foo><test>1</test></foo>
    """
    test_tag: str = "test"
    output_etree: List[Element] = xml_utils.dict_to_etree(test_tag, input_data)
    output_children: List[Element] = list(output_etree[0])

    assert len(output_etree) == 1
    assert output_etree[0].tag == test_tag
    assert output_etree[0].text is None
    assert len(output_children) == len(input_data)
    for out_child in output_children:
        assert out_child.tag in list(input_data.keys())


def test_dict_to_etree__dict_recursion() -> None:
    """
    Test converting a nested dictionary to an ElementTree.Element.

    Given a nested dictionary, the function should create a hierarchical structure of
    ElementTree.Elements with the corresponding tags and values.

    For example:
    - Input: tag: foo, dict: {"bar": {"test": 1, "john": {"doe": 1}}}
    - Expected XML:
        <foo>
            <bar>
                <test>1</test>
                <john>
                    <doe>1</doe>
                </john>
            </bar>
        </foo>
    """
    test_tag: str = "foo"
    input_dict: dict = {"bar": {"test": 1, "john": {"doe": 1}}}

    output_etree: List[Element] = xml_utils.dict_to_etree(test_tag, input_dict)

    assert len(output_etree) == 1
    assert output_etree[0].tag == test_tag
    assert output_etree[0].text is None
    children: List[Element] = list(output_etree[0])
    assert len(children) == 1
    assert children[0].tag == "bar"
    assert children[0].text is None
    children = list(children[0])
    assert len(children) == 2
    assert children[0].tag == "test"
    assert children[0].text == 1
    assert children[1].tag == "john"
    assert children[1].text is None
    children = list(children[1])
    assert len(children) == 1
    assert children[0].tag == "doe"
    assert children[0].text == 1


@pytest.mark.parametrize("input_data", [[1, 2, 3, 4], ["a", "b", "c", "d"]])
def test_dict_to_etree__primitive_list(input_data: list) -> None:
    """
    Test converting a primitive list to multiple ElementTree.Elements.

    Given a list of primitive values (int/str), the function should create multiple
    ElementTree.Elements, each with the given tag and corresponding value.

    For example:
    - Input: tag: foo, dict: [1, 2, 3, 4]
    - Expected XML:
        <foo>1</foo>
        <foo>2</foo>
        <foo>3</foo>
        <foo>4</foo>
    """
    test_tag: str = "foo"

    output_etree: List[Element] = xml_utils.dict_to_etree(test_tag, input_data)

    assert len(output_etree) == len(input_data)

    for actual_etree, expected_data in zip(output_etree, input_data):
        assert actual_etree.text == expected_data


def test_dict_to_etree__list_with_dicts_or_sub_lists() -> None:
    """
    Test converting a list with dictionaries or sub-lists to multiple ElementTree.Elements.

    Given a list containing dictionaries or sub-lists, the function should create multiple
    ElementTree.Elements, each representing the corresponding dictionary or sub-list.

    For example:
    - Input: tag: foo, dict: [{"bar": 1}, {"bar": 2}, {"bar": 3}]
    - Expected XML:
        <foo>
            <bar>1</bar>
            <bar>2</bar>
            <bar>3</bar>
        </foo>
    """
    test_tag: str = "foo"
    input_list: List[dict] = [{"bar": 1}, {"bar": 2}, {"bar": 3}]
    output_etree: List[Element] = xml_utils.dict_to_etree(test_tag, input_list)

    assert len(output_etree) == 1
    children: List[Element] = list(output_etree[0])
    assert len(children) == 3
    assert children[0].tag == "bar"
    assert children[0].text == 1
    assert children[1].tag == "bar"
    assert children[1].text == 2
    assert children[2].tag == "bar"
    assert children[2].text == 3


@pytest.mark.parametrize("input_data", [{}, []])
def test_dict_to_etree__empty_input(input_data: Union[dict, list]) -> None:
    """
    Test that when an empty dictionary or an empty list is passed as input,
    the function returns an empty Element with the provided tag.

    Example:
    - Input: tag: foo, dict: {}
    - Expected Output: <foo/>

    - Input: tag: foo, dict: []
    - Expected Output: <foo/>
    """
    output_etree: List[Element] = xml_utils.dict_to_etree("test", input_data)
    assert len(output_etree) == 1
    assert output_etree[0].tag == "test"
    assert output_etree[0].text is None
    assert len(list(output_etree[0])) == 0


def test_dict_to_etree__nested_lists() -> None:
    """
    Test that when the input dictionary contains nested lists,
    the function correctly flattens and handles them and generates
    the corresponding XML elements.

    Example:
    - Input: tag: test, dict: {"foo": [[1, 2], [3, 4]]}
    - Expected Output:
        <test>
            <foo>1</foo>
            <foo>2</foo>
            <foo>3</foo>
            <foo>4</foo>
        </test>
    """
    input_dict: dict = {"foo": [[1, 2], [3, 4]]}
    output_etree: List[Element] = xml_utils.dict_to_etree("test", input_dict)

    assert len(output_etree) == 1
    assert output_etree[0].tag == "test"
    children: List[Element] = list(output_etree[0])
    assert len(children) == 4

    # check that all children have the same tag "foo"
    assert len(list(filter(lambda child: child.tag == "foo", children))) == 4
    assert children[0].text == 1
    assert children[1].text == 2
    assert children[2].text == 3
    assert children[3].text == 4


###############################
# --- ElementTree to Dict --- #
###############################


@pytest.fixture
def etree_root(request: pytest.FixtureRequest) -> Element:
    """
    Parameterized fixture, which expects a string in the request.param
    containing xml formatted text.
    :param request: pytest fixture request containing xml string.
    :return: Element
    """
    xml_string = request.param
    tree: ET.ElementTree = ET.ElementTree(ET.fromstring(xml_string))
    return tree.getroot()


@pytest.mark.parametrize(
    "etree_root",
    ["<test>1</test>", "<test>some_string</test>", "<test/>"],
    indirect=True,
)
def test_etree_to_dict__primitive_values(etree_root: Element) -> None:
    """
    Test converting an ElementTree.Element containing a primitive value to a dictionary.

    Given an ElementTree.Element with a single tag and a text content representing a primitive
    value, the function should convert it into a dictionary with the tag as the key and the
    text content as the value.

    Example:
    - Input: <test>1</test>
    - Expected Output: {"test": "1"}
    """
    output_dict: dict = xml_utils.etree_to_dict(etree_root)

    assert output_dict["test"] == etree_root.text
    assert len(output_dict) == 1


@pytest.mark.parametrize(
    "etree_root",
    [
        "<foo><bar>1</bar></foo>",
        "<foo><bar>some_string</bar></foo>",
    ],
    indirect=True,
)
def test_etree_to_dict__simple_children(etree_root: Element) -> None:
    """
    Test converting a simple ElementTree.Element with child elements to a dictionary.

    Given an ElementTree.Element with a single tag and one or more child elements,
    the function should convert it into a dictionary with the tag as the key and a nested dictionary
    representing the child elements.

    Example:
    - Input: <foo><bar>1</bar></foo>
    - Expected Output: {"foo": {"bar": "1"}}
    """
    output_dict: dict = xml_utils.etree_to_dict(etree_root)

    assert isinstance(output_dict["foo"], dict)
    assert len(output_dict) == len(list(etree_root))

    input_children: List[Element] = list(etree_root)
    for child in input_children:
        assert child.tag in list(output_dict["foo"].keys())


@pytest.mark.parametrize("etree_root", [
    "<foo><bar>1</bar><bar>2</bar></foo>",
    "<foo><bar>test</bar><bar>cat</bar></foo>",
], indirect=True)
def test_etree_to_dict__simple_tree(etree_root: Element) -> None:
    """
    Test converting an ElementTree.Element with multiple child elements of the same
    tag to a list in the dictionary.

    Given an ElementTree.Element with a single tag and multiple child elements of the same tag,
    the function should convert it into a dictionary with the tag as the key and a list of values
    representing the child elements.

    Example:
    - Input:
        <foo>
            <bar>1</bar>
            <bar>2</bar>
            <bar>3</bar>
        </foo>
    - Expected Output: {"foo": [{ "bar" : 1 }, {"bar": 2 }, {"bar" :3 }]}
    """
    output_dict: dict = xml_utils.etree_to_dict(etree_root)

    assert isinstance(output_dict["foo"], list)
    assert len(output_dict["foo"]) == len(list(etree_root))

    input_children: List[Element] = list(etree_root)
    for child in input_children:
        assert any(list(filter(lambda i: child.tag in list(i.keys()), output_dict["foo"])))


@pytest.mark.parametrize(
    "etree_root",
    [
        "<foo><bar><bob>1</bob><cat>2</cat></bar><john><bob>3</bob><cat>4</cat></john></foo>"
    ],
    indirect=True,
)
def test_etree_to_dict__multiple_nested_dicts(etree_root: Element) -> None:
    """
    Test converting an ElementTree.Element structure to a nested dictionary.

    Given an ElementTree.Element with a single tag and multiple child elements of different tags,
    the function should convert it into a dictionary containing a sub dictionary with the
    corresponding structures.

    Example:
    - Input:
        <foo>
            <bar>
                <bob>1</bob>
                <cat>2</cat>
            </bar>
            <john>
                <bob>3</bob>
                <cat>4</cat>
            </john>
        </foo>
    - Expected Output:
        {
            "foo": {
                "bar" : { "bob" : 1, "cat": 2 },
                "john" : { "bob" : 1, "cat": 2 }
            }
        }
    """
    output_dict: dict = xml_utils.etree_to_dict(etree_root)

    # foo should be a dict with two elements
    assert isinstance(output_dict["foo"], dict)

    # check "bar" : { "bob" : 1, "cat": 2 }
    for child_key in ["bar", "john"]:
        assert child_key in output_dict["foo"].keys()

        child_dict: dict = output_dict["foo"][child_key]
        assert "bob" in child_dict.keys()
        assert child_dict["bob"] is not None
        assert "cat" in list(child_dict.keys())
        assert child_dict["cat"] is not None
