#  Copyright: (c) 2023, Puzzle ITC, Fabio Bertagna <bertagna@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from dataclasses import dataclass, field, asdict, fields
from enum import Enum
from typing import List, Optional, Any
from xml.etree.ElementTree import Element

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


class ListEnum(Enum):
    """Enum class with some handy utility functions."""

    @classmethod
    def as_list(cls) -> List[str]:
        """
        Return a list
        Returns
        -------

        """
        return [entry.value for entry in cls]

    @classmethod
    def from_string(cls, value: str) -> "ListEnum":
        """
        Returns Enum value, from a given String.
        If no enum value can be mapped to the input string,
        ValueError is raised.
        Parameters
        ----------
        value: `str`
            String to be mapped to enum value

        Returns
        -------
        Enum value
        """
        for _key, _value in cls.__members__.items():
            if value in (_key, _value.value):
                return _value
        raise ValueError(f"'{cls.__name__}' enum not found for '{value}'")


class FirewallRuleAction(ListEnum):
    """Represents the rule filter policy."""

    PASS = "pass"
    BLOCK = "block"
    REJECT = "reject"


class FirewallRuleDirection(ListEnum):
    """Represents the rule direction."""

    IN = "in"
    OUT = "out"


class FirewallRuleProtocol(ListEnum):
    """Represents the protocol to filter in a rule."""

    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    TCP_UDP = "tcp/udp"
    ICMP = "icmp"
    ESP = "esp"
    AH = "ah"
    GRE = "gre"
    IGMP = "igmp"
    PIM = "pim"
    OSPF = "ospf"
    GGP = "ggp"
    IPENCAP = "ipencap"
    ST2 = "st2"
    CBT = "cbt"
    EGP = "egp"
    IGP = "igp"
    BBN_RCC = "bbn-rcc"
    NVP = "nvp"
    PUP = "pup"
    ARGUS = "argus"
    EMCON = "emcon"
    XNET = "xnet"
    CHAOS = "chaos"
    MUX = "mux"
    DCN = "dcn"
    HMP = "hmp"
    PRM = "prm"
    XNS_IDP = "xns-idp"
    TRUNK_1 = "trunk-1"
    TRUNK_2 = "trunk-2"
    LEAF_1 = "leaf-1"
    LEAF_2 = "leaf-2"
    RDP = "rdp"
    IRTP = "irtp"
    ISO_TP4 = "iso-tp4"
    NETBLT = "netblt"
    MFE_NSP = "mfe-nsp"
    MERIT_INP = "merit-inp"
    DCCP = "dccp"
    PC = "3pc"
    IDPR = "idpr"
    XTP = "xtp"
    DDP = "ddp"
    IDPR_CMTP = "idpr-cmtp"
    TP_PLUS_PLUS = "tp++"
    IL = "il"
    IPV6 = "ipv6"
    SDRP = "sdrp"
    IDRP = "idrp"
    RSVP = "rsvp"
    DSR = "dsr"
    BNA = "bna"
    I_NLSP = "i-nlsp"
    SWIPE = "swipe"
    NARP = "narp"
    MOBILE = "mobile"
    TLSP = "tlsp"
    SKIP = "skip"
    IPV6_ICMP = "ipv6-icmp"
    CFTP = "cftp"
    SAT_EXPAK = "sat-expak"
    KRYPTOLAN = "kryptolan"
    RVD = "rvd"
    IPPC = "ippc"
    SAT_MON = "sat-mon"
    VISA = "visa"
    IPCV = "ipcv"
    CPNX = "cpnx"
    CPHB = "cphb"
    WSN = "wsn"
    PVP = "pvp"
    BR_SAT_MON = "br-sat-mon"
    SUN_ND = "sun-nd"
    WB_MON = "wb-mon"
    WB_EXPAK = "wb-expak"
    ISO_IP = "iso-ip"
    VMTP = "vmtp"
    SECURE_VMTP = "secure-vmtp"
    VINES = "vines"
    TTP = "ttp"
    NSFNET_IGP = "nsfnet-igp"
    DGP = "dgp"
    TCF = "tcf"
    EIGRP = "eigrp"
    SPRITE_RPC = "sprite-rpc"
    LARP = "larp"
    MTP = "mtp"
    AX_25 = "ax.25"
    IPIP = "ipip"
    MICP = "micp"
    SCC_SP = "scc-sp"
    ETHERIP = "etherip"
    ENCAP = "encap"
    GMTP = "gmtp"
    IFMP = "ifmp"
    PNNI = "pnni"
    ARIS = "aris"
    SCPS = "scps"
    QNX = "qnx"
    A_N = "a/n"
    IPCOMP = "ipcomp"
    SNP = "snp"
    COMPAQ_PEER = "compaq-peer"
    IPX_IN_IP = "ipx-in-ip"
    CARP = "carp"
    PGM = "pgm"
    L2TP = "l2tp"
    DDX = "ddx"
    IATP = "iatp"
    STP = "stp"
    SRP = "srp"
    UTI = "uti"
    SMP = "smp"
    SM = "sm"
    PTP = "ptp"
    ISIS = "isis"
    CRTP = "crtp"
    CRUDP = "crudp"
    SPS = "sps"
    PIPE = "pipe"
    SCTP = "sctp"
    FC = "fc"
    RSVP_E2E_IGNORE = "rsvp-e2e-ignore"
    UDPLITE = "udplite"
    MPLS_IN_IP = "mpls-in-ip"
    MANET = "manet"
    HIP = "hip"
    SHIM6 = "shim6"
    WESP = "wesp"
    ROHC = "rohc"
    PFSYNC = "pfsync"
    DIVERT = "divert"


class IPProtocol(ListEnum):
    IPv4 = "inet"
    IPv6 = "inet6"
    IPv4_IPv6 = "inet46"


class StateType(ListEnum):
    NONE = "none"
    KEEP_STATE = "keep state"
    SLOPPY_STATE = "sloppy state"
    MODULATE_STATE = "modulate state"
    SYNPROXY_STATE = "synproxy state"


@dataclass
class Source:
    """Represents the source in a firewall rule"""

    any: bool = False
    # Add other source attributes as needed


@dataclass
class Destination:
    """Represents the destination in a firewall rule"""

    any: bool = False
    port: Optional[int] = None
    # Add other destination attributes as needed


@dataclass
class FirewallRule:
    """Used to represent a firewall rule."""

    interface: str
    uuid: Optional[str] = None
    type: FirewallRuleAction = FirewallRuleAction.PASS
    descr: Optional[str] = None
    quick: bool = False
    ipprotocol: IPProtocol = IPProtocol.IPv4
    direction: Optional[FirewallRuleDirection] = None
    protocol: FirewallRuleProtocol = FirewallRuleProtocol.ANY
    source_address: Optional[str] = None
    source_network: Optional[str] = None
    source_port: Optional[str] = None
    source_any: bool = False
    source_not: bool = False
    destination_address: Optional[str] = None
    destination_network: Optional[str] = None
    destination_port: Optional[str] = None
    destination_any: bool = False
    destination_not: bool = True
    disabled: bool = False
    log: bool = False
    category: Optional[str] = None
    statetype: StateType = StateType.KEEP_STATE

    # TODO ChangeLog

    @staticmethod
    def from_xml(element: Element) -> "FirewallRule":
        rule_dict: dict = xml_utils.etree_to_dict(element)["rule"]

        # we start with a dictionary from XML looking like this for example:
        # source : {
        #     any: 1,
        #     port: 22,
        #     address: 192.168.1.1/24,
        #     not: 1
        # }

        for direction in ["source", "destination"]:
            for key in ["address", "network", "port", "any", "not"]:
                if key in ["any", "not"]:
                    # 'any' and 'not' must be a boolean value, therefore None is treated as False
                    rule_dict[f"{direction}_{key}"] = (
                        key in rule_dict[direction] and rule_dict[direction][key] != 0
                    )
                else:
                    rule_dict[f"{direction}_{key}"] = rule_dict[direction].get(key)

            del rule_dict[direction]

        rule_dict["uuid"] = element.attrib.get("uuid")

        return FirewallRule(**rule_dict)

    def to_etree(self) -> Element:
        rule_dict: dict = asdict(self)
        del rule_dict["uuid"]

        for direction in ["source", "destination"]:
            for key in ["address", "network", "port", "any", "not"]:
                current_val: Optional[Any] = rule_dict.get(f"{direction}_{key}")
                if current_val is not None:

                    if rule_dict.get(direction) is None:
                        rule_dict[direction] = {}

                    if not (isinstance(current_val, bool) and current_val is False):
                        rule_dict[direction][key] = str(int(current_val))

                    del rule_dict[f"{direction}_{key}"]

        for rule_key, rule_val in rule_dict.copy().items():
            if rule_val is None or rule_val is False:
                del rule_dict[rule_key]

        element: Element = xml_utils.dict_to_etree("rule", rule_dict)[0]

        if self.uuid:
            element.attrib["uuid"] = self.uuid

        return element


class FirewallRuleSet(OPNsenseModuleConfig):
    _rules: List[FirewallRule]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(module_name="firewall_rules", path=path)
        print(self._config_map)
        self._rules = self._load_rules()

    def _load_rules(self) -> List[FirewallRule]:
        # /opnsense/filter Element containing a list of <rule>
        element_tree_rules: Element = self.get("rules")

        return [FirewallRule.from_xml(element) for element in element_tree_rules]

    @property
    def changed(self) -> bool:
        return self._load_rules() != self._rules

    def add_or_update(self, rule: FirewallRule) -> None:
        existing_rule: Optional[FirewallRule] = next((r for r in self._rules if r.uuid == rule.uuid), None)
        if existing_rule:
            existing_rule.__dict__.update(rule.__dict__)
        else:
            self._rules.append(rule)

    def delete(self, rule: FirewallRule) -> None:
        self._rules = [r for r in self._rules if r != rule]

    def find(self, **kwargs) -> Optional[FirewallRule]:
        for rule in self._rules:
            match = all(
                getattr(rule, key, None) == value for key, value in kwargs.items()
            )
            if match:
                return rule
        return None

    def findall(self, **kwargs) -> List[FirewallRule]:
        matching_rules = []
        for rule in self._rules:
            match = all(
                getattr(rule, key, None) == value for key, value in kwargs.items()
            )
            if match:
                matching_rules.append(rule)
        return matching_rules

    def save(self) -> bool:
        filter_element: Element = self._config_xml_tree.find(self._config_map["rules"])

        self._config_xml_tree.remove(filter_element)
        filter_element.clear()
        filter_element.extend([rule.to_etree() for rule in self._rules])
        self._config_xml_tree.append(filter_element)

        return super().save()
