# Opnsense Collection for Ansible

[![CI](https://github.com/puzzle/puzzle.opnsense/workflows/CI/badge.svg?event=push)](https://github.com/puzzle/puzzle.opnsense/actions) [![Codecov](https://img.shields.io/codecov/c/github/puzzle/puzzle.opnsense)](https://codecov.io/gh/puzzle/puzzle.opnsense)

The Ansible Collection for OPNsense provides a comprehensive set of Ansible content to automate the configuration and
management of OPNsense instances. It offers a streamlined approach to deploy and maintain OPNsense firewalls and routing
platforms in a scalable and consistent manner.

## Using this collection

<!--Include some quick examples that cover the most common use cases for your collection content. It can include the following examples of installation and upgrade (change puzzle.opnsense correspondingly):-->

### Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install puzzle.opnsense
```

You can also include it in a `requirements.yml` file and install it
with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: puzzle.opnsense
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade
the `ansible` package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install puzzle.opnsense --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is
broken in the latest version (please report an issue in this repository). Use the following syntax to install
version `0.1.0`:

```bash
ansible-galaxy collection install puzzle.opnsense:==0.1.0
```

See [Ansible using collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more
details.

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html) in all
our interactions within this project.

If you encounter abusive behavior, please refer to
the [policy violations](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html#policy-violations) section
of the Code for information on how to raise a complaint.

## Communication

We announce releases and important changes through
Ansible's [The Bullhorn newsletter](https://github.com/ansible/community/wiki/News#the-bullhorn). Be sure you
are [subscribed](https://eepurl.com/gZmiEP).

Join us in the `#ansible` (general use questions and support), `#ansible-community` (community and collection
development questions), and
other [IRC channels](https://docs.ansible.com/ansible/devel/community/communication.html#irc-channels).

For more information about communication, refer to
the [Ansible Communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Contributing to this collection

The content of this collection is made by people like you, a community of individuals collaborating on making the world
better through developing automation software.

We are actively accepting new contributors.

Any kind of contribution is very welcome.

You don't know how to start? Refer to the [Ansible contribution guide](https://docs.ansible.com/ansible/devel/community/index.html)!

We use the following guidelines:

* [Ansible Contribution Guide](https://docs.ansible.com/ansible/devel/community/index.html)
* [Ansible Review Checklists](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_reviewing.html)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

## Collection maintenance

If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://docs.ansible.com/ansible/devel/community/maintainers.html).

## Governance

The process of decision-making in this collection is based on discussing and finding consensus among participants.

Every voice is important. If you have something on your mind, create an issue or dedicated discussion and let's discuss
it!

## Tested with Ansible

<!-- TODO List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

## External requirements

<!-- TODO List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->

## Release notes

See the [changelog](https://github.com/puzzle/puzzle.opnsense/tree/main/CHANGELOG.rst).

## Roadmap
 
We plan to regularly release minor and patch versions, whenever new features are added or bugs fixed. Our collection follows [semantic versioning](https://semver.org/), so breaking changes will only happen in major releases.

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/devel/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/main/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [News for Maintainers](https://github.com/ansible-collections/news-for-maintainers)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
