opnsense_configure - OPNsense configuration role
=========

This role provides a generic approach to configure OPNsense instances by populating host variables
according to this roles defaults specification.

Role Variables
--------------

The variables must be structured in a way that each puzzle.opnsense module has its own variable section . Each module related variable section
is then structured just like the corresponding module parameters as documented in the modules themselves.
The top level structure must be structured as follows:
```yaml
---
system:
  access:
    users: [] # list of users, where the users follows the system_access_users module parameter structure
  high_availability:
    # system_high_availability_settings module parameters
  settings:
    general:
      # system_settings_general module parameters
    logging:
      # system_settings_logging module parameters
    
interfaces:
  assignments: [] # list of interface assignments, where the users follows the interfaces_configuration module parameter structure

firewall:
  aliases: [] # list of aliases, where the users follows the firewall_alias module parameter structure
  rules: [] # list of rules, where the users follows the firewall_rules module parameter structure
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
      access:
        users:
          - username: simple_user
            password: pass1234
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
          - aliases
          - rules
          - ipsec
      settings:
        general:
          hostname: "firewall01"
          domain: "test.local"
          timezone: "Europe/Zurich"
        logging:
          preserve_logs: 10
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
    firewall:
      aliases:
        - name: TestAliasTypeHost
          type: host
          statistics: false
          description: Test Alias with type Host
          content: 10.0.0.1
        - name: TestAliasTypeNetwork
          type: network
          statistics: false
          description: Test Alias with type Network
          content: 10.0.0.0/24
      rules:
        - interface: lan
          description: Block SSH on LAN
          destination:
            port: 22
          action: block
  roles:
    - role: puzzle.opnsense.opnsense_configure

```

License
-------

GPLv3

Author Information
------------------
 - Fabio Bertagna (github.com/dongiovanni83)
