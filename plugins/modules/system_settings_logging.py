#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""system_settings_logging module: Module to configure opnsense logging"""

__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''
---
author:
  - Reto Kupferschmid (@rekup)
module: system_settings_logging
short_description: Configure logging settings.
description:
  - Module to configure system logging
options:
  preserve_logs:
    description:
      - Number of logs to preserve. By default 31 logs are preserved.
      - When no max filesize is offered or the logs are smaller than the the size requested, this equals the number of days, e.g. V(10)
    type: int
    required: false
  max_log_file_size_mb:
    description:
      - Maximum file size per log file, e.g. V(5)
      - When set and a logfile exceeds the amount specified, it will be rotated
      - This option is available in OPNsense 24.1 and newer
    type: int
    required: false
'''

EXAMPLES = r'''
- name: Set the number of logs to preserve to 10
  puzzle.opnsense.system_settings_logging:
    preserve_logs: 10

- name: Set max log file size to 5MB
  puzzle.opnsense.system_settings_logging:
    max_log_file_size_mb: 5
'''

RETURN = '''
opnsense_configure_output:
    description: A List of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: system_syslog_start
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: 'Configuring system logging...done.'
        stdout_lines:
          - 'Configuring system logging...done.'
'''
# fmt: on

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
    ModuleMisconfigurationError,
    UnsupportedModuleSettingError,
)


def is_positive_int(number: int) -> bool:
    """
    Validates number is positive int

    :param number: The input number to check

    :return: True if the provided number is a positive int, False if it isn't
    """

    # https://github.com/opnsense/core/blob/24.1/src/www/diag_logs_settings.php#L80
    return isinstance(number, int) and number > 0


def main():
    """
    Main function of the system_settings_logging module
    """

    module_args = {
        "preserve_logs": {"type": "int", "required": False},
        "max_log_file_size_mb": {"type": "int", "required": False},
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    preserve_logs_param = module.params.get("preserve_logs")
    max_log_file_size_mb_param = module.params.get("max_log_file_size_mb")

    with OPNsenseModuleConfig(
        module_name="system_settings_logging",
        config_context_names=["system_settings_logging"],
        check_mode=module.check_mode,
    ) as config:
        if preserve_logs_param:
            if not is_positive_int(preserve_logs_param):
                module.fail_json(msg="Preserve logs must be a positive integer value")

            # if the current preserve_los value is not set in the config XML
            # config.get("preserve_logs") will be None
            if config.get("preserve_logs") is not None:
                current_preserve_logs_setting = int(config.get("preserve_logs").text)
            else:
                current_preserve_logs_setting = ""
            if preserve_logs_param != current_preserve_logs_setting:
                config.set(value=str(preserve_logs_param), setting="preserve_logs")

        if max_log_file_size_mb_param:
            if not is_positive_int(max_log_file_size_mb_param):
                module.fail_json(msg="Max file size must be a positive integer value")

            # if the current max_log_file_size_mb value is not set in the config XML
            # config.get("max_log_file_size_mb") will be None
            try:
                if config.get("max_log_file_size_mb") is not None:
                    current_max_log_file_size_mb = int(config.get("max_log_file_size_mb").text)
                else:
                    current_max_log_file_size_mb = ""
                if max_log_file_size_mb_param != current_max_log_file_size_mb:
                    config.set(
                        value=str(max_log_file_size_mb_param),
                        setting="max_log_file_size_mb",
                    )
            except (UnsupportedModuleSettingError, ModuleMisconfigurationError) as exc:
                module.fail_json(
                    msg="Parameter max_log_file_size_mb is not"
                        f"supported in {exc.opnsense_version}"
                )


        if config.changed:
            result["diff"] = config.diff
            result["changed"] = True
        if config.changed and not module.check_mode:
            config.save()
            result["opnsense_configure_output"] = config.apply_settings()
            for cmd_result in result["opnsense_configure_output"]:
                if cmd_result["rc"] != 0:
                    module.fail_json(
                        msg="Apply of the OPNsense settings failed",
                        details=cmd_result,
                    )

    # Return results
    module.exit_json(**result)


if __name__ == "__main__":
    main()
