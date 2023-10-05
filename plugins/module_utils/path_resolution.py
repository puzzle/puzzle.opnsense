# Copyright: (c) 2023, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""path resolution utility"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

path_resolution = {
    'OPNsense 22.7 (amd64/OpenSSL)': {
        'sysctl': 'sysctl',
        'system': 'system',
        'theme': 'theme',
    },
    'OPNsense 23.1': {
        'sysctl': 'sysctl',
        'system': 'system',
        'theme': 'theme',
    },
}

class PathResolutionError(Exception):
    """
    Execption class for pathresolution
    """
    def __init__(self, version, path_key = None):

        if not version:
            super().__init__(f"version {version} was not found")

        if not path_key:
            super().__init__(f"path {path_key} was not found" if path_key else "")

def resolve_path(version, path_key):
    """



    funtion that either returns the resolved path to a specific version or
    returns an error
    """
    if version in path_resolution and path_key in path_resolution[version]:
        return path_resolution[version][path_key]
    else:
        raise PathResolutionError(version, path_key)
