---
name: OPNsense version update
about: Track adding support for a new OPNsense release and dropping the oldest one
title: 'chore: support OPNsense <NEW_VERSION>, drop <OLD_VERSION>'
labels: maintenance, opnsense-update
assignees: ''

---

## Summary

Track the maintenance work required to support a newly released OPNsense version and drop the oldest one.

The collection supports **at most 4 OPNsense versions** at a time.

- **New OPNsense version to add:** `<NEW_VERSION>` (e.g. `25.1`)
- **OPNsense version to drop:** `<OLD_VERSION>`
- **OPNsense versions still supported after this update:** `<v1>`, `<v2>`, `<v3>`, `<NEW_VERSION>`
- **Upstream release notes:** <link to https://docs.opnsense.org/releases.html entry>

## Python / Ansible support matrix impact

- [ ] Determined the oldest Python shipped by each still-supported OPNsense version
- [ ] Identified Python version(s) to drop (if any): `<pyX.Y>`
- [ ] Identified `ansible-core` version(s) to drop: per
  the [support matrix](https://docs.ansible.com/projects/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix),
  drop every `ansible-core` version whose **lowest supported control-node Python equals the dropped `pyX.Y`**. Keep
  `ansible-core` versions whose minimum control-node Python is higher than `pyX.Y`. Versions to drop:
  `<ansible-core X.Y>`
- [ ] `Pipfile` / `Pipfile.lock` resolves on the new minimum Python

Files to update consistently:

- [ ] `tests/config.yml`
- [ ] `.github/workflows/ansible-test.yml`
- [ ] `docs/docsite/rst/development_guide.rst`
- [ ] `Pipfile` / `Pipfile.lock`
- [ ] Any other CI/molecule/Makefile helper pinning Python or Ansible

## Module review

For each module in `plugins/modules/`, decide and check off:

| Module                              | Still legacy? | MVC/API upstream? | Action                    |
|-------------------------------------|---------------|-------------------|---------------------------|
| `firewall_alias`                    | yes/no        | yes/no            | keep / update / deprecate |
| `firewall_rules`                    | yes/no        | yes/no            | keep / update / deprecate |
| `interfaces_configuration`          | yes/no        | yes/no            | keep / update / deprecate |
| `system_access_users`               | yes/no        | yes/no            | keep / update / deprecate |
| `system_high_availability_settings` | yes/no        | yes/no            | keep / update / deprecate |
| `system_settings_general`           | yes/no        | yes/no            | keep / update / deprecate |
| `system_settings_logging`           | yes/no        | yes/no            | keep / update / deprecate |

For every still-supported module:

- [ ] Entry added in `plugins/module_utils/module_index.py` for `<NEW_VERSION>`
- [ ] `php_requirements`/ `configure_functions` verified against
- [ ] XPaths of settings in the moduel_index verified against `opnsense-core@<tag>`
- [ ] Behavioral parity preserved for older still-supported versions

For each deprecated module:

- [ ] `meta/runtime.yml` `plugin_routing.modules.<name>.deprecation` block added with `removal_version` and
  `warning_text`
- [ ] `removal_version` set to **current collection major + 3** (rationale: with strict 4-version support and one
  major bump per OPNsense version drop, the legacy module is still required by the 3 older OPNsense versions in the
  current window; after 3 more cycles those have all been dropped and removal is safe)
- [ ] `warning_text` names the API-based replacement
- [ ] Module `DOCUMENTATION` `deprecated:` block added, matching `removal_version` and `warning_text`
- [ ] Module still functional until removal (no behavior change)

## Molecule scenarios

- [ ] New OPNsense `<NEW_VERSION>` VM/platform added to scenarios of every still-supported module
- [ ] No VM/platform entry created for the dropped `<OLD_VERSION>`
- [ ] Scenarios for still-supported older versions left intact

## Branches and MRs

Per the upgrade workflow, split work into focused branches/MRs:

- [ ] `chore/drop-python-<X>-ansible-<Y>` — support matrix changes
- [ ] `feat/opnsense-<NEW_VERSION>-support` — new version support across `module_index.py` and molecule
- [ ] `fix/<module>-opnsense-<NEW_VERSION>` — per-module fixes where upstream changed (one branch per module if
  non-trivial)
- [ ] `chore/deprecate-<module>` — one branch per deprecation (or grouped if trivially related)

Each branch must:

- [ ] Include a changelog fragment under `changelogs/fragments/`
- [ ] **Not** edit `changelogs/changelog.yaml` or `CHANGELOG.rst`
- [ ] Use conventional commits (`feat|fix|chore|docs|refactor|ci|test(scope): description`)

## Verification

- [ ] `ansible-lint` clean
- [ ] `ansible-test sanity` green against the new matrix
- [ ] `ansible-test units` green
- [ ] `molecule test` green for touched modules, including a run against `<NEW_VERSION>`
- [ ] CI pipeline green on each MR

## Release

- [ ] All MRs merged
- [ ] `galaxy.yml` `version` bumped per the policy below
- [ ] Tag pushed and CI publishes the new collection version

### Versioning policy

The collection enforces a strict **4-OPNsense-versions** support window. Bumps are:

- **Major (`X+1.0.0`)**: dropping an OPNsense version, removing a module, or any other change breaking users on a
  still-supported OPNsense release. Every "update" cycle that drops the oldest OPNsense version is therefore a
  major bump.
- **Minor (`X.Y+1.0`)**: adding support for a new OPNsense version (without dropping one), adding a module, marking
  a module as deprecated.
- **Patch (`X.Y.Z+1`)**: bug fixes, doc-only changes.

## References

- OPNsense releases: https://docs.opnsense.org/releases.html
- FreeBSD python port: https://github.com/freebsd/freebsd-ports/blob/main/Mk/bsd.default-versions.mk#L150
- Ansible support
  matrix: https://docs.ansible.com/projects/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix
- Python release status: https://devguide.python.org/versions/
