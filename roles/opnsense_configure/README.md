opnsense_configure - OPNsense configuration role
=========

This role provides a generic approach to configure OPNsense instances by populating host variables
according to this roles defaults specification.

Role Variables
--------------

The variables must be structured in a way that each puzzle.opnsense module has its own variable section. Each module related variable section
is then structured just like the corresponding module parameters as documented in the modules themselves.
The top level structure is as follows:
```yaml
---
system:
  high_availability:
    # system_high_availability_settings module parameters
  settings:
    general:
      # system_settings_general module parameters

interfaces:
  assignments: [] # list of interface assignments, follows the interfaces_assignments module parameter structure.
                 # Note: interfaces_assignments is deprecated and not supported on OPNsense 26.7.
```


Example Playbook
----------------

The usage of the role is straight forward, however the main thought should go into the building of the
host variables. An example execution could look like this:

```yaml
---
- name: converge
  hosts: all
  become: true
  vars:
    system:
      high_availability:
        synchronize_interface: LAN
        synchronize_config_to_ip: 224.0.0.240
        synchronize_peer_ip: 224.0.0.241
        disable_preempt: true
        disconnect_dialup_interfaces: true
        synchronize_states: true
        remote_system_username: opnsense
        remote_system_password: v3rys3cure
        services_to_synchronize:
          - ipsec
      settings:
        general:
          hostname: "firewall01"
          domain: "test.local"
          timezone: "Europe/Zurich"
    interfaces:
      assignments:
        - device: em0
          identifier: opt2
          description: VAGRANT
        - device: em1
          identifier: lan
          description: LAN
        - device: em2
          identifier: wan
          description: WAN
        - device: em3
          identifier: opt1
          description: DMZ
  roles:
    - role: puzzle.opnsense.opnsense_configure

```

License
-------

GPLv3

Author Information
------------------
 - Fabio Bertagna (github.com/dongiovanni83)
