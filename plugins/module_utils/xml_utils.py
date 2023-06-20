# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for XML operations."""

from __future__ import (absolute_import, division, print_function)

from typing import Union, Optional
from xml.etree.ElementTree import Element

__metaclass__ = type


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
        return _process_list(tag, data)


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
        for child in child_elements:
            new_element.append(child)
    return new_element


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
        if isinstance(data_item, (int, str, type(None))):
            new_items: list[Element] = dict_to_etree(tag, data_item)

            if len(new_items) != 1:
                raise AssertionError("Primitive or None type must return only a single element")

            new_elements.extend(new_items)

        elif isinstance(data_item, dict):
            root = _process_dict_list(tag, data_item, root)

    if root is not None:
        new_elements.append(root)

    return new_elements


def _process_dict_list(tag: str, data_item: dict, root: Optional[Element]) -> Optional[Element]:
    """
    Processes a dictionary within a list, converting its key-value pairs to ElementTree.Element.

    :param tag: The tag for the new elements.
    :param data_item: The dictionary containing key-value pairs.
    :param root: The root element to append child elements.
    :return: The updated root element.
    """
    if root is None:
        root = Element(tag)

    for key, val in data_item.items():
        child_elements: list[Element] = dict_to_etree(key, val)
        root.extend(child_elements)

    return root
