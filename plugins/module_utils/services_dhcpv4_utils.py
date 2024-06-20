from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)

class DHCPv4Set(OPNsenseModuleConfig):
    def __init__(self, interface, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="services_dhcpv4",
            config_context_names=["services_dhcpv4", "enable", "range_from", "range_to"],
            path=interface + path,
        )
