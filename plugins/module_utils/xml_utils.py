# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for XML operations."""

from __future__ import absolute_import, division, print_function

from typing import Union, Optional, List
from xml.etree.ElementTree import Element

__metaclass__ = type


###############################
# --- Dict to ElementTree --- #
###############################


def dict_to_etree(
    tag: str, data: Optional[Union[int, str, list, dict]]
) -> Optional[List[Element]]:
    """
    Converts a Python dictionary to an ElementTree.Element structure.

    :param tag: The root element tag.
    :param data: The root element children structure data.
    :return: The generated list of ElementTree.Element.
    """

    return_value = None

    if isinstance(data, (int, str, type(None))):
        return_value = [_create_element(tag, data)]

    elif isinstance(data, dict):
        return_value = [_create_element_from_dict(tag, data)]

    elif isinstance(data, list):
        flattened_data = _flatten_list(data)
        return_value = _process_list(tag, flattened_data)

    if return_value is not None:
        return return_value

    raise ValueError(
        f"You provided an unsupported data type {type(data)}."
        "Only values of type int, str, dict or list are supported."
    )


def _create_element(tag: str, data: Optional[Union[int, str]]) -> Element:
    """
    Creates an ElementTree.Element with the given tag and optional text content.

    :param tag: The element tag.
    :param data: The optional text content of the element.
    :return: The created ElementTree.Element.
    """
    new_element: Element = Element(tag)
    new_element.text = data
    return new_element


def _create_element_from_dict(tag: str, data: dict) -> Element:
    """
    Creates an ElementTree.Element from a dictionary by recursively converting its key-value pairs.

    :param tag: The tag for the new element.
    :param data: The dictionary containing key-value pairs.
    :return: The created ElementTree.Element.
    """
    new_element: Element = Element(tag)
    for key, val in data.items():
        child_elements: List[Element] = dict_to_etree(key, val)

        new_element.extend(child_elements)

    return new_element


def _flatten_list(data: list) -> list:
    """
    Flattens a nested list.

    :param data: The list to flatten.
    :return: The flattened list.
    """
    flattened_list = []
    for item in data:
        if isinstance(item, list):
            flattened_list.extend(_flatten_list(item))
        else:
            flattened_list.append(item)
    return flattened_list


def _process_list(tag: str, data: list) -> List[Element]:
    """
    Processes a list by iterating over its elements and converting them to ElementTree.Element.

    :param tag: The tag for the new elements.
    :param data: The list of elements to process.
    :return: The list of generated ElementTree.Element.
    """
    new_elements: List[Element] = []
    root: Optional[Element] = None

    if len(data) == 0:
        return [Element(tag)]

    for data_item in data:
        if isinstance(data_item, (int, str, type(None), list)):
            new_items: List[Element] = dict_to_etree(tag, data_item)

            new_elements.extend(new_items)

        elif isinstance(data_item, dict):
            root = _process_dict_list(tag, data_item, root)

    if root is not None:
        new_elements.append(root)

    return new_elements


def _process_dict_list(
    tag: str, input_dict: dict, root: Optional[Element]
) -> Optional[Element]:
    """
    Processes a dictionary within a list, converting its key-value pairs to ElementTree.Element.

    :param tag: The tag for the new elements.
    :param input_dict: The dictionary containing key-value pairs.
    :param root: The root element to append child elements.
    :return: The updated root element.
    """
    if root is None:
        root = Element(tag)

    for key, val in input_dict.items():
        child_elements: List[Element] = dict_to_etree(key, val)
        root.extend(child_elements)

    return root


###############################
# --- ElementTree to Dict --- #
###############################


def etree_to_dict(input_etree: Element) -> dict:
    """
    Converts an ElementTree.Element structure to a Python dictionary.

    :param input_etree: The input ElementTree.Element.
    :return: dict: The result dict.
    """

    input_children: List[Element] = list(input_etree)

    # input element has no children, so it is a 'primitive' element
    if len(input_children) == 0:
        return {input_etree.tag: input_etree.text}  # Return the text directly

    children_results = [etree_to_dict(child) for child in input_children]

    # If there's only one child node, return it as a dictionary
    if len(input_children) == 1:
        return {input_etree.tag: children_results[0]}

    # If all child tags are the same, wrap them in a list
    if len(set(child.tag for child in input_children)) == 1:
        return {input_etree.tag: children_results}

    result = {}
    for child_data in children_results:
        for key, value in child_data.items():
            if key in result:
                if isinstance(result[key], list):
                    result[key].append(value)
                else:
                    result[key] = [result[key], value]
            else:
                result[key] = value

    return {input_etree.tag: result}


def elements_equal(e1, e2) -> bool:
    """
    Compare two XML elements for equality.
    Args:
        e1 (Element): The first XML element.
        e2 (Element): The second XML element.
    Returns:
        bool: True if the elements are equal, False otherwise.
    """

    # Check basic attributes for equality
    if len(e1) != len(e2) or e1.attrib != e2.attrib or e1.tag != e2.tag:
        return False

    # Leaf elements with no children
    if len(e1) == 0 and len(e2) == 0:
        # 1. Check if texts are exactly the same (ignoring whitespaces and None)
        # 2. or check if one text is '1' and the other is None with no children
        e1_text: Optional[str] = "" if e1.text is None else str(e1.text).strip()
        e2_text: Optional[str] = "" if e2.text is None else str(e2.text).strip()

        return (
            e1_text == e2_text
            or (e1_text == "1" and e2_text == "")
            or (e2_text == "1" and e1_text == "")
        )

    # Tags have children
    return all(
        elements_equal(c1, c2)
        for c1, c2 in zip(
            sorted(e1, key=lambda x: x.tag), sorted(e2, key=lambda x: x.tag)
        )
    )
