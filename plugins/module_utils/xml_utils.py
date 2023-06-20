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

                            <foo>1</foo>
    { "foo" : [1,2,3] } =>  <foo>2</foo>
                            <foo>3</foo>

    {                                           <foo>
        "foo" : [                                   <bar>1</bar>
            {"bar":1},{"bar":2},{"bar":3}   =>      <bar>2</bar>
        ]                                           <bar>3</bar>
    }                                           </foo>


    {                                           <foo>
        "foo" : [                                   <bar>1</bar>
            {"bar":1},{"bob":2},{"cat":3}   =>      <bob>2</bob>
        ]                                           <cat>3</cat>
    }                                           </foo>

    {
        "foo" : [
            1,
            { "bar": 2 },
            [ 3,4,5 ],
            [{ "bob": 2 },{ "bob": 2 },{ "bob": 2 }]

    }
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
        for data_item in data:
            new_items: list[Element] = dict_to_etree(tag, data_item)
            for item in new_items:
                new_elements.append(item)
        return new_elements
