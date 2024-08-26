=================================
OPNsense Collection Release Notes
=================================

.. contents:: Topics

v1.4.0
======

New Modules
-----------

- firewall_alias - Configure firewall aliases.

v1.3.0
======

Major Changes
-------------

- @kdhlab added general OPNsense 24.7 support to the collection
- system_high_availability_settings - Refactoring for 24.7 support

v1.2.1
======

Bugfixes
--------

- firewall_rules_utils - Handle additional XML attributes for the firewall rule objects from the config.

v1.2.0
======

Minor Changes
-------------

- config_utils - Raise exceptions that occur within an OPNsenseConfigContext with traceback.
- system_access_users - Enhanced group removal handling

Bugfixes
--------

- interfaces_assignments - Include plugin interfaces such as VLAN, VXLANs etc. in validations.
- module_index - Password entry now matches configure_function structure.
- system_access_users - Introduced password sanitization to fix parsing errors.
- system_access_users - Introduced password verification to fix passwords not being updated.
- system_access_users - Remove the UserLoginEnum type to prevent strict validation.
- system_access_users - Updated set_user_password dict calls in order to work with the newly introduced structure
- system_access_users - apikeys are changed if updated
- system_access_users - apikeys parameters are now passed as a list of dicts

New Modules
-----------

- system_high_availability_settings - Configure high availability settings

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
