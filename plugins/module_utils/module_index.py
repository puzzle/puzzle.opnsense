#  Copyright: (c) 2023, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
VERSION_MAP is a dictionary that defines the mapping of configuration settings, PHP requirements,
and configure functions for different versions of OPNsense. Each key in this dictionary represents
a specific version of OPNsense, and the value is another dictionary that outlines the configurations
for that version.

Structure of VERSION_MAP:
- The top-level keys are strings representing OPNsense versions
  (e.g., "OPNsense 22.7 (amd64/OpenSSL)").
- Each value under a version key is a nested dictionary that maps module names to
  their specific configurations.
- Each module's configuration includes keys for settings (with XPath values),
  PHP requirements, and configure functions.

For example, the 'system_settings_general' module for "OPNsense 22.7 (amd64/OpenSSL)" includes:
- Setting mappings: These are key-value pairs where the key is a friendly name for a setting
  (e.g., 'hostname'), and the value is the XPath in the OPNsense configuration file to access
  this setting (e.g., 'system/hostname').
- PHP requirements: A list of file paths required for executing the configure functions when
  applying changes.
- Configure functions: A dictionary mapping function names to their details. Each function
  detail includes the function name and any parameters required to execute the function.

This map is essential for dynamically configuring modules based on the OPNsense version and
provides a centralized definition for various configurations across different OPNsense versions.
"""

VERSION_MAP = {
    "OPNsense 22.7 (amd64/OpenSSL)": {
        "system_settings_general": {
            "hostname": "system/hostname",
            "domain": "system/domain",
            "timezone": "system/timezone",
            # Add other mappings here.
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "system_timezone_configure": {
                    "name": "system_timezone_configure",
                    "configure_params": ["true"],
                },
                "system_trust_configure": {
                    "name": "system_trust_configure",
                    "configure_params": ["true"],
                },
                "system_hostname_configure": {
                    "name": "system_hostname_configure",
                    "configure_params": ["true"],
                },
                "system_hosts_generate": {
                    "name": "system_hosts_generate",
                    "configure_params": ["true"],
                },
                "system_resolvconf_generate": {
                    "name": "system_resolvconf_generate",
                    "configure_params": ["true"],
                },
                "plugins_configure_dns": {
                    "name": "plugins_configure",
                    "configure_params": ["'dns'", "true"],
                },
                "plugins_configure_dhcp": {
                    "name": "plugins_configure",
                    "configure_params": ["'dhcp'", "true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": ["true"],
                },
            },
        }
    },
    "OPNsense 23.1": {
        "system_settings_general": {
            "hostname": "system/hostname",
            "domain": "system/domain",
            "timezone": "system/timezone",
            # Add other mappings here
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "system_timezone_configure": {
                    "name": "system_timezone_configure",
                    "configure_params": ["true"],
                },
                "system_trust_configure": {
                    "name": "system_trust_configure",
                    "configure_params": ["true"],
                },
                "system_hostname_configure": {
                    "name": "system_hostname_configure",
                    "configure_params": ["true"],
                },
                "system_hosts_generate": {
                    "name": "system_hosts_generate",
                    "configure_params": ["true"],
                },
                "system_resolvconf_generate": {
                    "name": "system_resolvconf_generate",
                    "configure_params": ["true"],
                },
                "plugins_configure_dns": {
                    "name": "plugins_configure",
                    "configure_params": ["'dns'", "true"],
                },
                "plugins_configure_dhcp": {
                    "name": "plugins_configure",
                    "configure_params": ["'dhcp'", "true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": ["true"],
                },
            },
        },
    },
}
