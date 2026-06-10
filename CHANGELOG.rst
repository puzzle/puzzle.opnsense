=================================
OPNsense Collection Release Notes
=================================

.. contents:: Topics

v3.0.0
======

Minor Changes
-------------

- CI matrix updated to test against ``ansible-core`` 2.18, 2.19 and ``devel`` on Python 3.11, 3.12 and 3.13.
- module_index - add OPNsense 26.1 to VERSION_MAP for interfaces_assignments and system_settings_general

Breaking Changes / Porting Guide
--------------------------------

- The minimum supported ``ansible-core`` is now 2.18. ``ansible-core`` 2.12 through 2.17 are no longer tested or supported, as their lowest supported control-node Python is below the new floor.
- The minimum supported control-node Python is now 3.11. Python 3.8, 3.9 and 3.10 are no longer supported.
- ci - raise minimum Python to 3.11 and drop ansible-core <2.18 support; add ansible-core 2.18/2.19/2.20 and Python 3.13/3.14 to CI matrix
- module_index - drop OPNsense 24.1 from VERSION_MAP

Deprecated Features
-------------------

- firewall_alias - will be removed in version 4.0.0; use oxlorg.opnsense.alias instead
- firewall_rules - will be removed in version 4.0.0; use oxlorg.opnsense.rule instead
- system_high_availability_settings - will be removed in version 5.0.0; use oxlorg.opnsense.hasync_general and oxlorg.opnsense.hasync_service instead
- system_settings_logging - will be removed in version 4.0.0; use oxlorg.opnsense.syslog instead

Removed Features (previously deprecated)
----------------------------------------

- system_access_users - will be removed in version 4.0.0; use oxlorg.opnsense.user, oxlorg.opnsense.group and oxlorg.opnsense.privilege instead

Bugfixes
--------

- interfaces_assignments - add OPNsense 26.1 molecule platform, remove 24.1
- system_settings_general - update configure functions for OPNsense 26.1 (system_resolver_configure replaces system_trust_configure/system_hosts_generate/system_resolvconf_generate); add 26.1 molecule platform, remove 24.1

v2.0.0
======

Major Changes
-------------

- OPNsense 25.7 support

Minor Changes
-------------

- plugins.module_utils.xml_utils:elements_equal - Fix element content comparison behaviour

Breaking Changes / Porting Guide
--------------------------------

- OPNsense 22.7 support has been dropped.
- OPNsense 23.1 support has been dropped.
- OPNsense 23.7 support has been dropped.

Deprecated Features
-------------------

- firewall_alias - Use oxlorg.opnsense.alias instead
- firewall_rules - Use oxlorg.opnsense.rule instead
- system_access_users - Use oxlorg.opnsense.user, oxlorg.opnsense.group and oxlorg.opnsense.privilege instead.
- system_high_availability_settings - Use oxlorg.opnsense.hasync_general and oxlorg.opnsense.hasync_service instead.
- system_settings_logging - Use oxlorg.opnsense.syslog instead

v1.5.0
======

Minor Changes
-------------

- puzzle.opnsense.opnsense_configure - Addition of an ansible role to the collection

Bugfixes
--------

- puzzle.opnsense.system_access_users - Thanks to @GBBx fixed a bug which falsely adds empty parameters to user instance.
- puzzle.opnsense.system_access_users - Thanks to @GBBx fixed a bug while user deletion.

v1.4.1
======

Bugfixes
--------

- system_settings_logging - fix XPath migrations for settings in 24.7.

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
