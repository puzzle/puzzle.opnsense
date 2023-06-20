# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for XML operations."""
from __future__ import (absolute_import, division, print_function)

from typing import Union, Optional
from xml.etree.ElementTree import Element

__metaclass__ = type


def dict_to_etree(tag: str, data: Optional[Union[int, str, list, dict]]) -> list[Element]:
    """
    Generates a python dictionary to an ElementTree.Element.

    :param tag: root element tag
    :param data: root element children structure data
    :return: generated ElementTree.Element
    """
    if isinstance(data, int) or isinstance(data, str) or data is None:
        new_element: Element = Element(tag)
        new_element.text = data
        return [new_element]

    elif isinstance(data, dict):
        new_element: Element = Element(tag)
        for key, val in data.items():
            child_elements: list[Element] = dict_to_etree(key, val)
            for child in child_elements:
                new_element.append(child)

        return [new_element]

    elif isinstance(data, list):
        new_elements: list[Element] = []
        root: Optional[Element] = None

        for data_item in data:
            # primitive list elements
            if isinstance(data_item, int) or isinstance(data_item, str) or data_item is None:
                new_items: list[Element] = dict_to_etree(tag, data_item)

                if len(new_items) != 1:
                    raise AssertionError("Primitive or None type must return only a single element")

                for item in new_items:
                    new_elements.append(item)

            # dict list elements
            elif isinstance(data_item, dict):
                if root is None:
                    root = Element(tag)
                for key, val in data_item.items():
                    child_elements: list[Element] = dict_to_etree(key, val)
                    for child in child_elements:
                        root.append(child)

        if root is not None:
            new_elements.append(root)
        return new_elements
