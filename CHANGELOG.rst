=================================
OPNsense Collection Release Notes
=================================

.. contents:: Topics

v1.1.1
======

Bugfixes
--------

- system_access_users_utils - Handle additional XML attributes of user objects that are not yet handled by the system_access_users module.

v1.1.0
======

Bugfixes
--------

- version_util - Use `product_series` for version detection to avoid minor version mismatches.

New Modules
-----------

- interfaces_assignments - This module can be used to assign interfaces to network ports and network IDs to new interfaces.

v1.0.0
======

New Modules
-----------

- firewall_rules - This module is used to manage OPNSense firewall rules
- system_access_users - Manage OPNsense users
- system_settings_general - Configure general settings mainly concern network-related settings like the hostname.
- system_settings_logging - Configure logging settings.
