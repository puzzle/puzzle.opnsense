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
# pylint: disable=duplicate-code; Since this is rewritten in some tests.
VERSION_MAP = {
    "22.7": {
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
        },
        "system_settings_logging": {
            "preserve_logs": "syslog/preservelogs",
            # Add other mappings here
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_settings_logging": {
                    "name": "system_syslog_start",
                    "configure_params": ["true"],
                },
            },
        },
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "password": {
            "php_requirements": [
                "/usr/local/etc/inc/auth.inc",
            ],
            "configure_functions": {
                "name": "echo password_hash",
                "configure_params": [
                    "'password'",
                    "PASSWORD_BCRYPT",
                    "[ 'cost' => 11 ]",
                ],
            },
        },
        "firewall_rules": {
            "rules": "filter",
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": ["true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "interfaces_assignments": {
            "interfaces": "interfaces",
            # Add other mappings here.
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/rrd.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "system_high_availability_settings": {
            # Add other mappings here
            "parent_node": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "aliases": "hasync/synchronizealiases",
            "auth_servers": "hasync/synchronizeauthservers",
            "captive_portal": "hasync/synchronizecaptiveportal",
            "certificates": "hasync/synchronizecerts",
            "cron": "hasync/synchronizecron",
            "dhcpd": "hasync/synchronizedhcpd",
            "dhcpdv6": "hasync/synchronizedhcpdv6",
            "dhcpv4_relay": "hasync/synchronizedhcrelay6",
            "dhcpv6_relay": "hasync/synchronizedhcrelay",
            "dashboard": "hasync/synchronizewidgets",
            "dnsmasq_dns": "hasync/synchronizednsforwarder",
            "frr": "hasync/",
            "firewall_categories": "hasync/synchronizecategories",
            "firewall_groups": "hasync/synchronizeifgroups",
            "firewall_log_templates": "hasync/synchronizelvtemplate",
            "firewall_rules": "hasync/synchronizerules",
            "firewall_schedules": "hasync/synchronizeschedules",
            "ipsec": "hasync/synchronizeipsec",
            "intrusion_detection": "hasync/synchronizesuricata",
            "kea_dhcp": "hasync/synchronizekea",
            "monit_system_monitoring": "hasync/synchronizemonit",
            "nat": "hasync/synchronizenat",
            "netflow_insight": "hasync/synchronizesyslog",
            "network_time": "hasync/synchronizentpd",
            "openssh": "hasync/synchronizessh",
            "openvpn": "hasync/synchronizeopenvpn",
            "shaper": "hasync/synchronizeshaper",
            "static_routes": "hasync/synchronizestaticroutes",
            "system_tunables": "hasync/synchronizesysctl",
            "unbound_dns": "hasync/synchronizednsresolver",
            "user_and_groups": "hasync/synchronizeusers",
            "virtual_ips": "hasync/synchronizevirtualip",
            "web_gui": "hasync/synchronizewebgui",
            "web_proxy": "hasync/synchronizesquid",
            "wireguard": "hasync/synchronizewireguard",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
            ],
            "configure_functions": {},
        },
    },
    "23.1": {
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
        "system_settings_logging": {
            "preserve_logs": "syslog/preservelogs",
            # Add other mappings here
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_settings_logging": {
                    "name": "system_syslog_start",
                    "configure_params": ["true"],
                },
            },
        },
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "password": {
            "php_requirements": [
                "/usr/local/etc/inc/auth.inc",
            ],
            "configure_functions": {
                "name": "echo password_hash",
                "configure_params": [
                    "'password'",
                    "PASSWORD_BCRYPT",
                    "[ 'cost' => 11 ]",
                ],
            },
        },
        "firewall_rules": {
            "rules": "filter",
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",  # required for the service_log utility
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": ["true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "interfaces_assignments": {
            "interfaces": "interfaces",
            # Add other mappings here.
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/rrd.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "system_high_availability_settings": {
            # Add other mappings here
            "parent_node": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "aliases": "hasync/synchronizealiases",
            "auth_servers": "hasync/synchronizeauthservers",
            "captive_portal": "hasync/synchronizecaptiveportal",
            "certificates": "hasync/synchronizecerts",
            "cron": "hasync/synchronizecron",
            "dhcpd": "hasync/synchronizedhcpd",
            "dhcpdv6": "hasync/synchronizedhcpdv6",
            "dhcpv4_relay": "hasync/synchronizedhcrelay6",
            "dhcpv6_relay": "hasync/synchronizedhcrelay",
            "dashboard": "hasync/synchronizewidgets",
            "dnsmasq_dns": "hasync/synchronizednsforwarder",
            "frr": "hasync/",
            "firewall_categories": "hasync/synchronizecategories",
            "firewall_groups": "hasync/synchronizeifgroups",
            "firewall_log_templates": "hasync/synchronizelvtemplate",
            "firewall_rules": "hasync/synchronizerules",
            "firewall_schedules": "hasync/synchronizeschedules",
            "ipsec": "hasync/synchronizeipsec",
            "intrusion_detection": "hasync/synchronizesuricata",
            "kea_dhcp": "hasync/synchronizekea",
            "monit_system_monitoring": "hasync/synchronizemonit",
            "nat": "hasync/synchronizenat",
            "netflow_insight": "hasync/synchronizesyslog",
            "network_time": "hasync/synchronizentpd",
            "openssh": "hasync/synchronizessh",
            "openvpn": "hasync/synchronizeopenvpn",
            "shaper": "hasync/synchronizeshaper",
            "static_routes": "hasync/synchronizestaticroutes",
            "system_tunables": "hasync/synchronizesysctl",
            "unbound_dns": "hasync/synchronizednsresolver",
            "user_and_groups": "hasync/synchronizeusers",
            "virtual_ips": "hasync/synchronizevirtualip",
            "web_gui": "hasync/synchronizewebgui",
            "web_proxy": "hasync/synchronizesquid",
            "wireguard": "hasync/synchronizewireguard",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
            ],
            "configure_functions": {},
        },
    },
    "23.7": {
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
        "system_settings_logging": {
            "preserve_logs": "syslog/preservelogs",
            # Add other mappings here
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_settings_logging": {
                    "name": "system_syslog_start",
                    "configure_params": ["true"],
                }
            },
        },
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "password": {
            "php_requirements": [
                "/usr/local/etc/inc/auth.inc",
            ],
            "configure_functions": {
                "name": "echo password_hash",
                "configure_params": [
                    "'password'",
                    "PASSWORD_BCRYPT",
                    "[ 'cost' => 11 ]",
                ],
            },
        },
        "firewall_rules": {
            "rules": "filter",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": ["true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "interfaces_assignments": {
            "interfaces": "interfaces",
            # Add other mappings here.
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/rrd.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "system_high_availability_settings": {
            # Add other mappings here
            "parent_node": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "aliases": "hasync/synchronizealiases",
            "auth_servers": "hasync/synchronizeauthservers",
            "captive_portal": "hasync/synchronizecaptiveportal",
            "certificates": "hasync/synchronizecerts",
            "cron": "hasync/synchronizecron",
            "dhcpd": "hasync/synchronizedhcpd",
            "dhcpdv6": "hasync/synchronizedhcpdv6",
            "dhcpv4_relay": "hasync/synchronizedhcrelay6",
            "dhcpv6_relay": "hasync/synchronizedhcrelay",
            "dashboard": "hasync/synchronizewidgets",
            "dnsmasq_dns": "hasync/synchronizednsforwarder",
            "frr": "hasync/",
            "firewall_categories": "hasync/synchronizecategories",
            "firewall_groups": "hasync/synchronizeifgroups",
            "firewall_log_templates": "hasync/synchronizelvtemplate",
            "firewall_rules": "hasync/synchronizerules",
            "firewall_schedules": "hasync/synchronizeschedules",
            "ipsec": "hasync/synchronizeipsec",
            "intrusion_detection": "hasync/synchronizesuricata",
            "kea_dhcp": "hasync/synchronizekea",
            "monit_system_monitoring": "hasync/synchronizemonit",
            "nat": "hasync/synchronizenat",
            "netflow_insight": "hasync/synchronizesyslog",
            "network_time": "hasync/synchronizentpd",
            "openssh": "hasync/synchronizessh",
            "openvpn": "hasync/synchronizeopenvpn",
            "shaper": "hasync/synchronizeshaper",
            "static_routes": "hasync/synchronizestaticroutes",
            "system_tunables": "hasync/synchronizesysctl",
            "unbound_dns": "hasync/synchronizednsresolver",
            "user_and_groups": "hasync/synchronizeusers",
            "virtual_ips": "hasync/synchronizevirtualip",
            "web_gui": "hasync/synchronizewebgui",
            "web_proxy": "hasync/synchronizesquid",
            "wireguard": "hasync/synchronizewireguard",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
            ],
            "configure_functions": {},
        },
    },
    "24.1": {
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
        "system_settings_logging": {
            "preserve_logs": "syslog/preservelogs",
            "max_log_file_size_mb": "syslog/maxfilesize",
            # Add other mappings here
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {
                "system_settings_logging": {
                    "name": "system_syslog_start",
                    "configure_params": ["true"],
                }
            },
        },
        "system_access_users": {
            "users": "system/user",
            "uid": "system/nextuid",
            "gid": "system/nextgid",
            "system": "system",
            "php_requirements": [
                "/usr/local/etc/inc/system.inc",
            ],
            "configure_functions": {},
        },
        "password": {
            "php_requirements": [
                "/usr/local/etc/inc/auth.inc",
            ],
            "configure_functions": {
                "name": "echo password_hash",
                "configure_params": [
                    "'password'",
                    "PASSWORD_BCRYPT",
                    "[ 'cost' => 11 ]",
                ],
            },
        },
        "firewall_rules": {
            "rules": "filter",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/filter.inc",
            ],
            "configure_functions": {
                "system_cron_configure": {
                    "name": "system_cron_configure",
                    "configure_params": ["true"],
                },
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "interfaces_assignments": {
            "interfaces": "interfaces",
            # Add other mappings here.
            "php_requirements": [
                "/usr/local/etc/inc/config.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/filter.inc",
                "/usr/local/etc/inc/system.inc",
                "/usr/local/etc/inc/rrd.inc",
                "/usr/local/etc/inc/interfaces.inc",
            ],
            "configure_functions": {
                "filter_configure": {
                    "name": "filter_configure",
                    "configure_params": [],
                },
            },
        },
        "system_high_availability_settings": {
            # Add other mappings here
            "parent_node": "hasync",
            "synchronize_states": "hasync/pfsyncenabled",
            "synchronize_interface": "hasync/pfsyncinterface",
            "synchronize_peer_ip": "hasync/pfsyncpeerip",
            "synchronize_config_to_ip": "hasync/synchronizetoip",
            "remote_system_username": "hasync/username",
            "remote_system_password": "hasync/password",
            "aliases": "hasync/synchronizealiases",
            "auth_servers": "hasync/synchronizeauthservers",
            "captive_portal": "hasync/synchronizecaptiveportal",
            "certificates": "hasync/synchronizecerts",
            "cron": "hasync/synchronizecron",
            "dhcpd": "hasync/synchronizedhcpd",
            "dhcpdv6": "hasync/synchronizedhcpdv6",
            "dhcpv4_relay": "hasync/synchronizedhcrelay6",
            "dhcpv6_relay": "hasync/synchronizedhcrelay",
            "dashboard": "hasync/synchronizewidgets",
            "dnsmasq_dns": "hasync/synchronizednsforwarder",
            "frr": "hasync/",
            "firewall_categories": "hasync/synchronizecategories",
            "firewall_groups": "hasync/synchronizeifgroups",
            "firewall_log_templates": "hasync/synchronizelvtemplate",
            "firewall_rules": "hasync/synchronizerules",
            "firewall_schedules": "hasync/synchronizeschedules",
            "ipsec": "hasync/synchronizeipsec",
            "intrusion_detection": "hasync/synchronizesuricata",
            "kea_dhcp": "hasync/synchronizekea",
            "monit_system_monitoring": "hasync/synchronizemonit",
            "nat": "hasync/synchronizenat",
            "netflow_insight": "hasync/synchronizesyslog",
            "network_time": "hasync/synchronizentpd",
            "openssh": "hasync/synchronizessh",
            "openvpn": "hasync/synchronizeopenvpn",
            "shaper": "hasync/synchronizeshaper",
            "static_routes": "hasync/synchronizestaticroutes",
            "system_tunables": "hasync/synchronizesysctl",
            "unbound_dns": "hasync/synchronizednsresolver",
            "user_and_groups": "hasync/synchronizeusers",
            "virtual_ips": "hasync/synchronizevirtualip",
            "web_gui": "hasync/synchronizewebgui",
            "wireguard": "hasync/synchronizewireguard",
            "php_requirements": [
                "/usr/local/etc/inc/interfaces.inc",
                "/usr/local/etc/inc/util.inc",
                "/usr/local/etc/inc/config.inc",
            ],
            "configure_functions": {},
        },
    },
}
