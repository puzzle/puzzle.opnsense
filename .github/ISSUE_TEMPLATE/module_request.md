---
name: Ansible module request
about: Suggest a module for this collection
title: 'Module Request: MODULE_NAME'
labels: feature
assignees: ''

---

### Module Description

Briefly describe the functionality of the requested module.
Reference the OPNsense Web UI form the new module should implement, if possible with a screenshot.

### Minimum Viable Product (MVP)

Express your minimal viable product in the form of
the [Ansible `DOCUMENTATION` block format](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#documentation-block):

```yaml
module: module_name
short_description: Configure general settings mainly concern network-related settings like the hostname.
description:
  - Module to configure general system settings
options:
  opt_one:
    description: "The first example option.: V(firewall)"
    type: str
    required: false
```

### Examples

Mock up some usage examples in the form of
the [Ansible `EXAMPLES` block format](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#examples-block):

```yaml
---
- name: Example Task
  puzzle.opnsense.module_name:
    opt_one: "Firewall"
```

### Additional Notes (Optional)

* Mention any specific functionalities or edge cases to consider.
* Reference existing plugins or modules (if any) for inspiration or reference.
