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

    git clone git@github.com/<YOUR_GITHUB_HANDLE>/puzzle.opnsense \
       <YOUR_WORKING_DIR>/ansible_collections/puzzle/opnsense

3. Python 3.10 is used in this pipenv, therefore make sure you have this version on your system.
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


Testing Your Code
=================

These steps require for the local pipenv to be set up.

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
