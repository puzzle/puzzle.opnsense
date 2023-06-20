# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for XML operations."""

from __future__ import (absolute_import, division, print_function)

from typing import Union, Optional
from xml.etree.ElementTree import Element

__metaclass__ = type


###############################
# --- Dict to ElementTree --- #
###############################

def dict_to_etree(tag: str, data: Optional[Union[int, str, list, dict]]) -> list[Element]:
    """
    Converts a Python dictionary to an ElementTree.Element structure.

    :param tag: The root element tag.
    :param data: The root element children structure data.
    :return: The generated list of ElementTree.Element.
    """
    if isinstance(data, (int, str, type(None))):
        return [_create_element(tag, data)]

    elif isinstance(data, dict):
        return [_create_element_from_dict(tag, data)]

    elif isinstance(data, list):
        flattened_data = _flatten_list(data)
        return _process_list(tag, flattened_data)

    raise ValueError("Only values of type int, str, dict or list are supported.")


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
        child_elements: list[Element] = dict_to_etree(key, val)

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


def _process_list(tag: str, data: list) -> list[Element]:
    """
    Processes a list by iterating over its elements and converting them to ElementTree.Element.

    :param tag: The tag for the new elements.
    :param data: The list of elements to process.
    :return: The list of generated ElementTree.Element.
    """
    new_elements: list[Element] = []
    root: Optional[Element] = None

    if len(data) == 0:
        return [Element(tag)]

    for data_item in data:
        if isinstance(data_item, (int, str, type(None), list)):
            new_items: list[Element] = dict_to_etree(tag, data_item)

            new_elements.extend(new_items)

        elif isinstance(data_item, dict):
            root = _process_dict_list(tag, data_item, root)

    if root is not None:
        new_elements.append(root)

    return new_elements


def _process_dict_list(tag: str, input_dict: dict, root: Optional[Element]) -> Optional[Element]:
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
        child_elements: list[Element] = dict_to_etree(key, val)
        root.extend(child_elements)

    return root


###############################
# --- ElementTree to Dict --- #
###############################


def etree_to_dict(input_etree: Element) -> dict:
    """
    Converts an ElementTree.Element structure to a Python dictionary.

    :param input_etree: Input ElementTree.Element.
    :return: The generated dict.
    """
    input_children: list[Element] = list(input_etree)
    if len(input_children) > 0:
        new_children: list[dict] = []
        for child in input_children:
            new_children.append(etree_to_dict(child))

        if len(new_children) == 1:
            return {input_etree.tag: new_children[0]}
        return {input_etree.tag: new_children}
    return {input_etree.tag: input_etree.text}
