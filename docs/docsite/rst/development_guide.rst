.. _ansible_collections.puzzle.opnsense.docsite.development_guide:


****************************
Collection Development Guide
****************************


To contribute plugins to this collections a few things must be taken into
account when setting up a local development environment, such that the new code
can be tested. This guide intends to provide such instructions.


.. contents::
  :local:

Local Setup
===========

To have the collection setup correctly in your development environment, we
recommend you follow this setup guide. These steps are based on the official
Ansible documentation (`Prepare your environment
<https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html#prepare-your-environment>`__).

1. Create a fork of the repository to work on:
   https://github.com/puzzle/puzzle.opnsense/fork
2. Create a local collection directory from which you will develop the
   collection. **The cloned repository must be cloned into a folder following this
   path structure:** ``<YOUR_WORKING_DIR>/ansible_collections/puzzle/opnsense``.
   Therefore you could clone your fork like this:

   .. code-block:: shell-session

    git clone git@github.com/<YOUR_GITHUB_HANDLE>/puzzle.opnsense.git \
       <YOUR_WORKING_DIR>/ansible_collections/puzzle/opnsense

3. This collection supports Python versions >=3.6,<3.12 therefore make sure your system
   supports any of those versions.
4. Setup the pipenv:

   .. code-block:: shell-session

    pipenv install --dev

Your environment is now set up for local development and testing.


Developing New Plugins
======================

The following steps can guide you on how to add new code to this collection.

Collection Structure
--------------------
Before you start to develop new components familiarize yourself with the
structure of a collection. The most relevant part in the collection will
most likely be the plugins directory. When executed Ansible looks for plugins like e.g.
modules inside of the ``plugins`` directory, which requires to have additional
subfolders for each contained plugin type. The ``plugins`` directory could
therefore look like this:

.. code-block::

 puzzle.opnsense
  └─ plugins
      ├── modules
      └── module_utils


Reusable code and utilities must be added in the ``module_utils`` directory.
When these utils are needed e.g. in modules they must be imported using the
FQCN e.g. ``from ansible_collections.puzzle.opnsense.plugins.module_utils.xml_utils import XMLParser``.

The official Ansible Documentation (`Collection Structure
<https://docs.ansible.com/ansible/latest/dev_guide/developing_collections_structure.html#collection-structure>`__)
provides further reference regarding collection structure guidelines.

Using the OPNsense Module Config XML in Plugins
----------------------------------------

The ``OPNsenseModuleConfig`` utility module provides a convenient and efficient way to interact with the OPNsense configuration file located at ``/conf/config.xml`` within Ansible plugins. This utility is designed to offer a context manager that significantly simplifies the process of accessing, modifying, and managing configuration values in a structured and error-resistant manner.

It encapsulates the complexities associated with parsing and manipulating XML data, thereby allowing developers to concentrate on implementing task specific configuration logic.

Example
-------

The following is an illustrative example of utilizing the ``OPNsenseModuleConfig`` utility within an Ansible plugin:

.. code-block:: python

    from ansible_collections.puzzle.opnsense.plugins.module_utils import OPNsenseModuleConfig

    # Example usage within a plugin or module
    with OPNsenseModuleConfig(module_name='desired_module') as config:
        # Access a configuration value
        value = config.get_setting('setting_name')

        # Modify a configuration value
        config.set_module_setting(value='new_setting_value', setting='setting_name')

        # Apply changes and execute any necessary configure functions
        config.apply_settings()

        # Save changes to the configuration file
        config.save()

In this example:

- The ``with`` statement is used to instantiate ``OPNsenseModuleConfig`` with a specific module name.
- The ``get_setting`` method fetches a specific configuration value based on the setting name.
- The ``set_module_setting`` method updates a given setting with a new value.
- The ``apply_setting`` method applies the new settings and runs any required configure functions.
- The ``save`` method saves all changes back to the OPNsense config file.

This utility thus streamlines the interaction with the OPNsense configuration file, making it more manageable and less error-prone for developers working with Ansible plugins.


Version Mapping in OPNsense Configuration
-----------------------------------------

The ``VERSION_MAP`` is a crucial component in the OPNsense configuration utility module. It serves as a key-value mapping that aligns different OPNsense versions with their corresponding configuration settings, PHP requirements, and configure functions. This map ensures compatibility and accurate configuration across various versions of OPNsense.

Structure of VERSION_MAP
~~~~~~~~~~~~~~~~~~~~~~~~

- Top-Level Keys: Each top-level key represents a specific version of OPNsense, such as "OPNsense 22.7 (amd64/OpenSSL)".

- Module Configuration: The value associated with each OPNsense version key is a dictionary. This dictionary maps module names to their specific configuration settings.

- Configuration Details: For each module, the configuration includes:

  - **Setting Mappings**: Key-value pairs where the key represents a configuration setting (e.g., 'hostname') and the value is its corresponding XPath in the OPNsense configuration file.

  - **PHP Requirements**: A list of file paths necessary for the execution of PHP scripts related to the module.

  - **Configure Functions**: A dictionary of functions with details such as function name and parameters, necessary for module configuration.

Identifying PHP Requirements and Configure Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To identify the `php_requirements` and `configure_functions` for a specific module, one should refer to the OPNsense core GitHub repository. Within the repository, locate the PHP file corresponding to the module of interest (e.g., `core/src/www/system_general.php`). Examining this file will provide insights into the required PHP scripts and configurable functions for that module.

Purpose
~~~~~~~

``VERSION_MAP`` plays a critical role in ensuring that the OPNsense configuration utility can adapt to different versions of OPNsense. By providing version-specific paths and requirements, it allows the utility to read and modify configurations accurately, regardless of the OPNsense version in use.

Example
~~~~~~~

.. code-block:: python

    VERSION_MAP = {
        "OPNsense 22.7 (amd64/OpenSSL)": {
            "system_settings_general": {
                "hostname": "system/hostname",
                "domain": "system/domain",
                ...
                "php_requirements": [
                    "/usr/local/etc/inc/config.inc",
                    ...
                ],
                "configure_functions": {
                    "system_hostname_configure": {
                        "name": "system_hostname_configure",
                        ...
                    },
                    ...
                },
            }
        },
        "OPNsense 23.1": {
            ...
        },
    }

In this example, the configuration for "OPNsense 22.7 (amd64/OpenSSL)" is outlined, detailing settings, PHP requirements, and configure functions specific to the 'system_settings_general' module.

This detailed and version-specific mapping ensures the utility module operates correctly across different OPNsense releases, contributing significantly to the robustness and reliability of the configuration management process.


Using Molecule
=============

Run Ansible directly against a running instance of OPNsense managed by Molecule.
System requirements for this workflow is to have **vagrant** installed alongside with **virtualbox**.

1. Initialize a Molecule scenario
---------------------------------

If there is no Molecule scenario for your plugin, create one inside the
`molecule` directory, eg. `molecule/MY_SCENARIO`. This directory requires
a Molecule configuration YAML `molecule.yml`. The quickest setup is to copy
an existing example from a preexisting scenario. This file will look more
or less like this:

.. code-block:: yaml

    ---
    scenario:
        name: MY_SCENARIO
        test_sequence:
            - destroy
            - syntax
            - create
            - converge
            - idempotence
            - verify
            - destroy
    
    driver:
        name: vagrant
        parallel: true
    
    platforms:
        - name: "23.7"
          box: puzzle/opnsense
          hostname: false
          box_version: "23.7"
          memory: 1024
          cpus: 2
          instance_raw_config_args:
              - 'vm.guest = :freebsd'
              - 'ssh.sudo_command = "%c"'
              - 'ssh.shell = "/bin/sh"'
    
    provisioner:
        name: ansible
        env:
            ANSIBLE_VERBOSITY: 3
    verifier:
        name: ansible
        options:
            become: true

Now you are ready to start up your test VM using the following molecule
command:

.. code-block:: bash

    pipenv run molecule create --scenario-name MY_SCENARIO


.. note::

    Molecule leverages a sequence of different playbooks defined inside the
    `molecule.yml` in order to ensure execution and verification of ansible
    tests against a running instance. The full test sequence can be executed
    using `pipenv run molecule test`. However, like in this 'create' example
    we can run single stages such that we can eg. start the VM separately and
    control the teardown manually.


2. Add tests to your scenario
----------------------------

Molecule runs its scenario tests during its 'converge' stage.
Therefore your actual tests are required to be written inside a 
`molecule/MY_SCENARIO/converge.yaml` playbook, like for example:

.. code-block:: yaml

    ---
    - name: converge
      hosts: all
      become: true
      tasks:
        - name: Test MY_MODULE
          puzzle.opnsense.MY_MODULE:
            name: John
          register: output

        - name: Test output
          assert:
            that: 
              - "Hello John" == output.result


These tests can now be executed using molecule:

.. code-block:: bash

    pipenv run molecule converge --scenario-name MY_SCENARIO

3. Debug executions on your VM
------------------------------

If you want to inspect the OPNsense XML config you can connect to your
VM using vagrant. Since Molecule does not place Vagrantfiles inside the
collection directory you first need to identify your VM-id using:

.. code-block:: bash

    vagrant global-status

Select your VM-id and run:

.. code-block:: bash

    vagrant ssh YOUR_VM_ID


4. Poweroff your VM
-------------------


To cleanup your environment from any VM run:

.. code-block:: bash

    pipenv run molecule destroy --scenario-name MY_SCENARIO


Testing Your Code
=================

These steps require for the local pipenv to be set up. In addition to the pipenv
it is required to have **docker** installed as well. This is required by
``ansible-test`` such that all sanity and unit tests can be run in docker
environments against all supported Python versions configured in
``tests/config.yml``.

Local Unit Tests
----------------

The make target ``test-unit`` runs all unittests using ``ansible-test``.
Simply execute the following command:

.. code-block::

 make test-unit

Unittests generate a coverage report after each run which can be viewed using
the ``test-coverage-report`` make target:

.. code-block::

 make test-coverage-report


Local Sanity Tests
------------------

Sanity tests are executed using the ``test-sanity`` make target.

.. code-block::

 make test-sanity

Manual Testing
--------------

To test the collection locally in any Ansible setup make sure the Ansible
collection path is setup in a way, such that this collection can be found.
E.g. add an ``ansible.cfg`` which sets the ``collections_paths`` variable.
Here is important to note, that under ``collections_paths`` Ansible expects a
directory structure like this:

.. code-block::

 ansible_collections
  ├─ NAMESPACE_1
  │   ├── COLLECTION_1
  │   └── COLLECTION_2
  └─ puzzle
      └── opnsense

For further details regarding the ansible collection path configuration see the
documentation. (`Ansible Collection Path Doc
<https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths>`__)


Reviewing Code
=================

Prerequisite for a successful review is to have setup your environment according
to the section *Local Setup*. To review changes of other contributors use these
steps as a review guideline:

1. Clone the Fork or add it as a new remote:

   .. code-block::
    git remote add NEW_REMOTE_NAME REMOTE_URL
    git checkout NEW_REMOTE_NAME/BRANCH_NAME

   For example checking out the branch ``feature/review-guide`` of the fork
   ``dongiovanni83/puzzle.opnsense`` you would use this workflow:

   .. code-block::
    git remote add dongiovanni83 git@github.com:dongiovanni83/puzzle.opnsense.git
    git checkout dongiovanni83/feature/review-guide


2. If documentation has been added, build the site and check it locally:

   .. code-block::

    make build-doc

   Open the newly created docsite located in ``./dest/build/html/index.html`` and
   review the changes.

3. Run all tests locally:

   .. code-block::

    make test

4. Comment your Feedback directly in the Github PR.
