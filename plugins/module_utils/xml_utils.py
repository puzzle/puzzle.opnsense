# Copyright: (c) 2023, Fabio Bertagna <bertagna@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities for XML operations."""
from __future__ import (absolute_import, division, print_function)

from typing import Union
from xml.etree.ElementTree import Element

__metaclass__ = type


class XMLUtilsUnsupportedInputFormatError(Exception):
    pass


def _parse_children_from_dict() -> Element:
    pass


def dict_to_etree(input_dict: dict) -> Element:
    """
    Generates a python dictionary to an ElementTree.Element.
    :param input_dict: dictionary with input data
    :return: generated ElementTree.Element
    """
    input_dict_keys = list(input_dict.keys())

    if len(input_dict_keys) > 1:
        raise XMLUtilsUnsupportedInputFormatError(
            "xml_utils only support dictionaries using a single root entry."
        )

    input_tag = input_dict_keys[0]
    input_content: Union[int, str, list, dict] = input_dict[input_tag]

    if isinstance(input_content, list) or isinstance(input_content, dict):
        _parse_children_from_dict()

    new_element = Element(input_tag)
    new_element.text = input_content
    return new_element
