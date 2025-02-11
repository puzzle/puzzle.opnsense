#  Copyright: (c) 2024, Puzzle ITC
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: skip-file
import os
from tempfile import NamedTemporaryFile
from unittest.mock import patch
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import pytest
from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils import (
    InterfaceConfiguration,
    InterfacesSet,
    OPNSenseInterfaceNotFoundError,
    OPNSenseDeviceAlreadyAssignedError,
    OPNSenseGetInterfacesError,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.module_index import (
    VERSION_MAP,
)

# Test version map for OPNsense versions and modules
TEST_VERSION_MAP = {
    "OPNsense Test": {
        "interfaces_configuration": {
            "interfaces": "interfaces",
            "php_requirements": [],
            "configure_functions": {},
        },

    }
}

# pylint: disable=C0301
TEST_XML: str = """<?xml version="1.0"?>
                <opnsense>
                <lastchange/>
                <theme>opnsense</theme>
                <sysctl>
                    <item>
                    <descr>Disable the pf ftp proxy handler.</descr>
                    <tunable>debug.pfftpproxy</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Increase UFS read-ahead speeds to match current state of hard drives and NCQ. More information here: http://ivoras.sharanet.org/blog/tree/2010-11-19.ufs-read-ahead.html</descr>
                    <tunable>vfs.read_max</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Set the ephemeral port range to be lower.</descr>
                    <tunable>net.inet.ip.portrange.first</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Drop packets to closed TCP ports without returning a RST</descr>
                    <tunable>net.inet.tcp.blackhole</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Do not send ICMP port unreachable messages for closed UDP ports</descr>
                    <tunable>net.inet.udp.blackhole</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Randomize the ID field in IP packets (default is 0: sequential IP IDs)</descr>
                    <tunable>net.inet.ip.random_id</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr> Source routing is another way for an attacker to try to reach non-routable addresses behind your box. It can also be used to probe for information about your internal networks. These functions come enabled as part of the standard FreeBSD core system. </descr>
                    <tunable>net.inet.ip.sourceroute</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr> Source routing is another way for an attacker to try to reach non-routable addresses behind your box. It can also be used to probe for information about your internal networks. These functions come enabled as part of the standard FreeBSD core system. </descr>
                    <tunable>net.inet.ip.accept_sourceroute</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr> Redirect attacks are the purposeful mass-issuing of ICMP type 5 packets. In a normal network, redirects to the end stations should not be required. This option enables the NIC to drop all inbound ICMP redirect packets without returning a response. </descr>
                    <tunable>net.inet.icmp.drop_redirect</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr> This option turns off the logging of redirect packets because there is no limit and this could fill up your logs consuming your whole hard drive. </descr>
                    <tunable>net.inet.icmp.log_redirect</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Drop SYN-FIN packets (breaks RFC1379, but nobody uses it anyway)</descr>
                    <tunable>net.inet.tcp.drop_synfin</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Enable sending IPv4 redirects</descr>
                    <tunable>net.inet.ip.redirect</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Enable sending IPv6 redirects</descr>
                    <tunable>net.inet6.ip6.redirect</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Enable privacy settings for IPv6 (RFC 4941)</descr>
                    <tunable>net.inet6.ip6.use_tempaddr</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Prefer privacy addresses and use them over the normal addresses</descr>
                    <tunable>net.inet6.ip6.prefer_tempaddr</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Generate SYN cookies for outbound SYN-ACK packets</descr>
                    <tunable>net.inet.tcp.syncookies</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Maximum incoming/outgoing TCP datagram size (receive)</descr>
                    <tunable>net.inet.tcp.recvspace</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Maximum incoming/outgoing TCP datagram size (send)</descr>
                    <tunable>net.inet.tcp.sendspace</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Do not delay ACK to try and piggyback it onto a data packet</descr>
                    <tunable>net.inet.tcp.delayed_ack</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Maximum outgoing UDP datagram size</descr>
                    <tunable>net.inet.udp.maxdgram</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Handling of non-IP packets which are not passed to pfil (see if_bridge(4))</descr>
                    <tunable>net.link.bridge.pfil_onlyip</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Set to 0 to disable filtering on the incoming and outgoing member interfaces.</descr>
                    <tunable>net.link.bridge.pfil_member</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Set to 1 to enable filtering on the bridge interface</descr>
                    <tunable>net.link.bridge.pfil_bridge</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Allow unprivileged access to tap(4) device nodes</descr>
                    <tunable>net.link.tap.user_open</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Randomize PID's (see src/sys/kern/kern_fork.c: sysctl_kern_randompid())</descr>
                    <tunable>kern.randompid</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Maximum size of the IP input queue</descr>
                    <tunable>net.inet.ip.intr_queue_maxlen</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Disable CTRL+ALT+Delete reboot from keyboard.</descr>
                    <tunable>hw.syscons.kbd_reboot</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Enable TCP extended debugging</descr>
                    <tunable>net.inet.tcp.log_debug</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Set ICMP Limits</descr>
                    <tunable>net.inet.icmp.icmplim</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>TCP Offload Engine</descr>
                    <tunable>net.inet.tcp.tso</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>UDP Checksums</descr>
                    <tunable>net.inet.udp.checksum</tunable>
                    <value>default</value>
                    </item>
                    <item>
                    <descr>Maximum socket buffer size</descr>
                    <tunable>kern.ipc.maxsockbuf</tunable>
                    <value>default</value>
                    </item>
                </sysctl>
                <system>
                    <optimization>normal</optimization>
                    <hostname>OPNsense</hostname>
                    <domain>localdomain</domain>
                    <dnsallowoverride/>
                    <group>
                    <name>admins</name>
                    <descr>System Administrators</descr>
                    <scope>system</scope>
                    <gid>1999</gid>
                    <member>0</member>
                    <member>1000</member>
                    <member>2000</member>
                    <priv>user-shell-access</priv>
                    <priv>page-all</priv>
                    </group>
                    <user>
                    <name>root</name>
                    <descr>System Administrator</descr>
                    <scope>system</scope>
                    <groupname>admins</groupname>
                    <password>$2b$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS</password>
                    <uid>0</uid>
                    </user>
                    <user>
                    <password>$2y$10$1BvUdvwM.a.dJACwfeNfAOgNT6Cqc4cKZ2F6byyvY8hIK9I8fn36O</password>
                    <scope>user</scope>
                    <name>vagrant</name>
                    <descr>vagrant box management</descr>
                    <expires/>
                    <authorizedkeys/>
                    <ipsecpsk/>
                    <otp_seed/>
                    <shell>/bin/sh</shell>
                    <uid>1000</uid>
                    </user>
                    <nextuid>2001</nextuid>
                    <nextgid>2000</nextgid>
                    <timezone>Etc/UTC</timezone>
                    <time-update-interval>300</time-update-interval>
                    <timeservers>0.nl.pool.ntp.org</timeservers>
                    <webgui>
                    <protocol>https</protocol>
                    <ssl-certref>5a3951eaa0f49</ssl-certref>
                    </webgui>
                    <disablenatreflection>yes</disablenatreflection>
                    <usevirtualterminal>1</usevirtualterminal>
                    <disableconsolemenu/>
                    <disablechecksumoffloading>1</disablechecksumoffloading>
                    <disablesegmentationoffloading>1</disablesegmentationoffloading>
                    <disablelargereceiveoffloading>1</disablelargereceiveoffloading>
                    <ipv6allow/>
                    <powerd_ac_mode>hadp</powerd_ac_mode>
                    <powerd_battery_mode>hadp</powerd_battery_mode>
                    <powerd_normal_mode>hadp</powerd_normal_mode>
                    <bogons>
                    <interval>monthly</interval>
                    </bogons>
                    <kill_states/>
                    <enablesshd/>
                    <ssh>
                    <enabled>enabled</enabled>
                    <permitrootlogin>1</permitrootlogin>
                    <passwordauth>0</passwordauth>
                    </ssh>
                    <backupcount>60</backupcount>
                    <crypto_hardware>aesni</crypto_hardware>
                    <backup>
                    <nextcloud version="1.0.0">
                    <enabled>0</enabled>
                    <url/>
                    <user/>
                    <password/>
                    <password_encryption/>
                    <backupdir>OPNsense-Backup</backupdir>
                    </nextcloud>
                    </backup>
                    <firmware version="1.0.1">
                    <mirror/>
                    <flavour/>
                    <plugins/>
                    <type/>
                    <subscription/>
                    <reboot/>
                    </firmware>
                </system>
                <interfaces>
                    <wan>
                        <if>em2</if>
                        <ipaddr>dhcp</ipaddr>
                        <dhcphostname/>
                        <mtu/>
                        <subnet/>
                        <gateway/>
                        <media/>
                        <mediaopt/>
                        <blockbogons>1</blockbogons>
                        <ipaddrv6>dhcp6</ipaddrv6>
                        <dhcp6-ia-pd-len>0</dhcp6-ia-pd-len>
                        <blockpriv>1</blockpriv>
                        <descr>WAN</descr>
                        <lock>1</lock>
                    </wan>
                    <lan>
                        <if>em1</if>
                        <descr>LAN</descr>
                        <enable>1</enable>
                        <lock>1</lock>
                        <spoofmac/>
                        <blockbogons>1</blockbogons>
                        <ipaddr>192.168.56.10</ipaddr>
                        <subnet>21</subnet>
                        <ipaddrv6>track6</ipaddrv6>
                        <track6-interface>wan</track6-interface>
                        <track6-prefix-id>0</track6-prefix-id>
                    </lan>
                    <opt1>
                        <if>em3</if>
                        <descr>DMZ</descr>
                        <spoofmac/>
                        <lock>1</lock>
                    </opt1>
                    <opt2>
                        <if>em0</if>
                        <descr>VAGRANT</descr>
                        <enable>1</enable>
                        <lock>1</lock>
                        <spoofmac/>
                        <ipaddr>dhcp</ipaddr>
                        <dhcphostname/>
                        <alias-address/>
                        <alias-subnet>32</alias-subnet>
                        <dhcprejectfrom/>
                        <adv_dhcp_pt_timeout/>
                        <adv_dhcp_pt_retry/>
                        <adv_dhcp_pt_select_timeout/>
                        <adv_dhcp_pt_reboot/>
                        <adv_dhcp_pt_backoff_cutoff/>
                        <adv_dhcp_pt_initial_interval/>
                        <adv_dhcp_pt_values>SavedCfg</adv_dhcp_pt_values>
                        <adv_dhcp_send_options/>
                        <adv_dhcp_request_options/>
                        <adv_dhcp_required_options/>
                        <adv_dhcp_option_modifiers/>
                        <adv_dhcp_config_advanced/>
                        <adv_dhcp_config_file_override/>
                    <adv_dhcp_config_file_override_path/>
                    </opt2>
                    <lo0>
                        <internal_dynamic>1</internal_dynamic>
                        <descr>Loopback</descr>
                        <enable>1</enable>
                        <if>lo0</if>
                        <ipaddr>127.0.0.1</ipaddr>
                        <ipaddrv6>::1</ipaddrv6>
                        <subnet>8</subnet>
                        <subnetv6>128</subnetv6>
                        <type>none</type>
                        <virtual>1</virtual>
                    </lo0>
                    <openvpn>
                        <internal_dynamic>1</internal_dynamic>
                        <enable>1</enable>
                        <if>openvpn</if>
                        <descr>OpenVPN</descr>
                        <type>group</type>
                        <virtual>1</virtual>
                        <networks/>
                    </openvpn>
                </interfaces>
                <dhcpd>
                <lan>
                <enable/>
                <range>
                <from>10.2.0.2</from>
                <to>10.2.0.200</to>
                </range>
                </lan>
                </dhcpd>
                <snmpd>
                <syslocation/>
                <syscontact/>
                <rocommunity>public</rocommunity>
                </snmpd>
                <syslog>
                <reverse/>
                </syslog>
                <nat>
                <outbound>
                <mode>automatic</mode>
                </outbound>
                </nat>
                <filter>
                <rule>
                <type>pass</type>
                <interface>wan</interface>
                <ipprotocol>inet</ipprotocol>
                <statetype>keep state</statetype>
                <descr>Allow SSH access</descr>
                <protocol>tcp</protocol>
                <source>
                <any/>
                </source>
                <destination>
                <any/>
                <port>22</port>
                </destination>
                </rule>
                <rule>
                <type>pass</type>
                <interface>wan</interface>
                <ipprotocol>inet</ipprotocol>
                <statetype>keep state</statetype>
                <descr>Allow incoming WebGUI access</descr>
                <protocol>tcp</protocol>
                <source>
                <any/>
                </source>
                <destination>
                <any/>
                <port>443</port>
                </destination>
                </rule>
                <rule>
                <type>pass</type>
                <ipprotocol>inet</ipprotocol>
                <descr>Default allow LAN to any rule</descr>
                <interface>lan</interface>
                <source>
                <network>lan</network>
                </source>
                <destination>
                <any/>
                </destination>
                </rule>
                <rule>
                <type>pass</type>
                <ipprotocol>inet6</ipprotocol>
                <descr>Default allow LAN IPv6 to any rule</descr>
                <interface>lan</interface>
                <source>
                <network>lan</network>
                </source>
                <destination>
                <any/>
                </destination>
                </rule>
                <rule>
                <type>pass</type>
                <interface>opt2</interface>
                <ipprotocol>inet</ipprotocol>
                <statetype>keep state</statetype>
                <descr>allow vagrant management</descr>
                <direction>in</direction>
                <quick>1</quick>
                <source>
                <any>1</any>
                </source>
                <destination>
                <any>1</any>
                </destination>
                <updated>
                <username>root@10.0.5.2</username>
                <time>1584202093.9701</time>
                <descr>/firewall_rules_edit.php made changes</descr>
                </updated>
                <created>
                <username>root@10.0.5.2</username>
                <time>1584202093.9701</time>
                <descr>/firewall_rules_edit.php made changes</descr>
                </created>
                </rule>
                </filter>
                <rrd>
                <enable/>
                </rrd>
                <load_balancer>
                <monitor_type>
                <name>ICMP</name>
                <type>icmp</type>
                <descr>ICMP</descr>
                <options/>
                </monitor_type>
                <monitor_type>
                <name>TCP</name>
                <type>tcp</type>
                <descr>Generic TCP</descr>
                <options/>
                </monitor_type>
                <monitor_type>
                <name>HTTP</name>
                <type>http</type>
                <descr>Generic HTTP</descr>
                <options>
                <path>/</path>
                <host/>
                <code>200</code>
                </options>
                </monitor_type>
                <monitor_type>
                <name>HTTPS</name>
                <type>https</type>
                <descr>Generic HTTPS</descr>
                <options>
                <path>/</path>
                <host/>
                <code>200</code>
                </options>
                </monitor_type>
                <monitor_type>
                <name>SMTP</name>
                <type>send</type>
                <descr>Generic SMTP</descr>
                <options>
                <send/>
                <expect>220 *</expect>
                </options>
                </monitor_type>
                </load_balancer>
                <widgets>
                <sequence>system_information-container:00000000-col3:show,services_status-container:00000001-col4:show,gateways-container:00000002-col4:show,interface_list-container:00000003-col4:show</sequence>
                <column_count>2</column_count>
                </widgets>
                <revision>
                <username>(root)</username>
                <time>1712239765.0467</time>
                <descr>Updated plugin interface configuration</descr>
                </revision>
                <OPNsense>
                <captiveportal version="1.0.1">
                <zones/>
                <templates/>
                </captiveportal>
                <Netflow version="1.0.1">
                <capture>
                <interfaces/>
                <egress_only>wan</egress_only>
                <version>v9</version>
                <targets/>
                </capture>
                <collect>
                <enable>0</enable>
                </collect>
                <activeTimeout>1800</activeTimeout>
                <inactiveTimeout>15</inactiveTimeout>
                </Netflow>
                <cron version="1.0.4">
                <jobs/>
                </cron>
                <Firewall>
                <Alias version="1.0.1">
                <geoip>
                <url/>
                </geoip>
                <aliases/>
                </Alias>
                <Lvtemplate version="0.0.1">
                <templates/>
                </Lvtemplate>
                <Category version="1.0.0">
                <categories/>
                </Category>
                <Filter version="1.0.3">
                <rules/>
                <snatrules/>
                <npt/>
                </Filter>
                </Firewall>
                <IDS version="1.0.9">
                <rules/>
                <policies/>
                <userDefinedRules/>
                <files/>
                <fileTags/>
                <general>
                <enabled>0</enabled>
                <ips>0</ips>
                <promisc>0</promisc>
                <interfaces>wan</interfaces>
                <homenet>192.168.0.0/16,10.0.0.0/8,172.16.0.0/12</homenet>
                <defaultPacketSize/>
                <UpdateCron/>
                <AlertLogrotate>W0D23</AlertLogrotate>
                <AlertSaveLogs>4</AlertSaveLogs>
                <MPMAlgo>ac</MPMAlgo>
                <detect>
                <Profile>medium</Profile>
                <toclient_groups/>
                <toserver_groups/>
                </detect>
                <syslog>0</syslog>
                <syslog_eve>0</syslog_eve>
                <LogPayload>0</LogPayload>
                <verbosity/>
                </general>
                </IDS>
                <Interfaces>
                <vxlans version="1.0.2"/>
                <loopbacks version="1.0.0"/>
                <neighbors version="1.0.0"/>
                </Interfaces>
                <monit version="1.0.12">
                <general>
                <enabled>0</enabled>
                <interval>120</interval>
                <startdelay>120</startdelay>
                <mailserver>127.0.0.1</mailserver>
                <port>25</port>
                <username/>
                <password/>
                <ssl>0</ssl>
                <sslversion>auto</sslversion>
                <sslverify>1</sslverify>
                <logfile>syslog facility log_daemon</logfile>
                <statefile/>
                <eventqueuePath/>
                <eventqueueSlots/>
                <httpdEnabled>0</httpdEnabled>
                <httpdUsername>root</httpdUsername>
                <httpdPassword>R4s6nqQWJXPYfQRNTVxvs3</httpdPassword>
                <httpdPort>2812</httpdPort>
                <httpdAllow/>
                <mmonitUrl/>
                <mmonitTimeout>5</mmonitTimeout>
                <mmonitRegisterCredentials>1</mmonitRegisterCredentials>
                </general>
                <alert uuid="f28abbf2-859a-4cfa-a56d-cb8b17449ffb">
                <enabled>0</enabled>
                <recipient>root@localhost.local</recipient>
                <noton>0</noton>
                <events/>
                <format/>
                <reminder>10</reminder>
                <descr/>
                </alert>
                <service uuid="f85a8cf8-a81e-4cf4-8cb0-c1fc2b10cb24">
                <enabled>1</enabled>
                <name>$HOST</name>
                <descr/>
                <type>system</type>
                <pidfile/>
                <match/>
                <path/>
                <timeout>300</timeout>
                <starttimeout>30</starttimeout>
                <address/>
                <interface/>
                <start/>
                <stop/>
                <tests>a60b489a-68c2-40e0-a29e-a3c54feb7116,eb557e4c-8ab0-4291-a58e-3f0871e4b65b,68e944f4-e4fb-415d-a4c5-465a20be0824,60b2a1e3-9607-4322-b759-55bfef6c2c37</tests>
                <depends/>
                <polltime/>
                </service>
                <service uuid="12aabe3a-3671-496d-aa9e-aa2018c766e3">
                <enabled>1</enabled>
                <name>RootFs</name>
                <descr/>
                <type>filesystem</type>
                <pidfile/>
                <match/>
                <path>/</path>
                <timeout>300</timeout>
                <starttimeout>30</starttimeout>
                <address/>
                <interface/>
                <start/>
                <stop/>
                <tests>27c5cee6-a3b0-47d7-9d49-1a71e97d7492</tests>
                <depends/>
                <polltime/>
                </service>
                <service uuid="325389a3-13df-4679-b0d3-1d238a83787b">
                <enabled>0</enabled>
                <name>carp_status_change</name>
                <descr/>
                <type>custom</type>
                <pidfile/>
                <match/>
                <path>/usr/local/opnsense/scripts/OPNsense/Monit/carp_status</path>
                <timeout>300</timeout>
                <starttimeout>30</starttimeout>
                <address/>
                <interface/>
                <start/>
                <stop/>
                <tests>cd4206a1-c857-461e-9740-e49d1a5821b0</tests>
                <depends/>
                <polltime/>
                </service>
                <service uuid="9c07f6fd-c55a-43fa-9513-363ac364b383">
                <enabled>0</enabled>
                <name>gateway_alert</name>
                <descr/>
                <type>custom</type>
                <pidfile/>
                <match/>
                <path>/usr/local/opnsense/scripts/OPNsense/Monit/gateway_alert</path>
                <timeout>300</timeout>
                <starttimeout>30</starttimeout>
                <address/>
                <interface/>
                <start/>
                <stop/>
                <tests>132a13e1-e2d5-4328-8ae8-7b7bd702d434</tests>
                <depends/>
                <polltime/>
                </service>
                <test uuid="86d2c560-3d56-449c-9d17-868beca7a939">
                <name>Ping</name>
                <type>NetworkPing</type>
                <condition>failed ping</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="e31f5c08-6b2e-47d6-8dfe-df66c5505f65">
                <name>NetworkLink</name>
                <type>NetworkInterface</type>
                <condition>failed link</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="81f2e1ca-d323-485b-9e4a-5a1ba5a460a0">
                <name>NetworkSaturation</name>
                <type>NetworkInterface</type>
                <condition>saturation is greater than 75%</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="a60b489a-68c2-40e0-a29e-a3c54feb7116">
                <name>MemoryUsage</name>
                <type>SystemResource</type>
                <condition>memory usage is greater than 75%</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="eb557e4c-8ab0-4291-a58e-3f0871e4b65b">
                <name>CPUUsage</name>
                <type>SystemResource</type>
                <condition>cpu usage is greater than 75%</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="68e944f4-e4fb-415d-a4c5-465a20be0824">
                <name>LoadAvg1</name>
                <type>SystemResource</type>
                <condition>loadavg (1min) is greater than 2</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="60b2a1e3-9607-4322-b759-55bfef6c2c37">
                <name>LoadAvg5</name>
                <type>SystemResource</type>
                <condition>loadavg (5min) is greater than 1.5</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="149c6e1f-7404-4af3-8761-54ed0c44a78a">
                <name>LoadAvg15</name>
                <type>SystemResource</type>
                <condition>loadavg (15min) is greater than 1</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="27c5cee6-a3b0-47d7-9d49-1a71e97d7492">
                <name>SpaceUsage</name>
                <type>SpaceUsage</type>
                <condition>space usage is greater than 75%</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="cd4206a1-c857-461e-9740-e49d1a5821b0">
                <name>ChangedStatus</name>
                <type>ProgramStatus</type>
                <condition>changed status</condition>
                <action>alert</action>
                <path/>
                </test>
                <test uuid="132a13e1-e2d5-4328-8ae8-7b7bd702d434">
                <name>NonZeroStatus</name>
                <type>ProgramStatus</type>
                <condition>status != 0</condition>
                <action>alert</action>
                <path/>
                </test>
                </monit>
                <OpenVPNExport version="0.0.1">
                <servers/>
                </OpenVPNExport>
                <proxy version="1.0.5">
                <general>
                <enabled>0</enabled>
                <error_pages>opnsense</error_pages>
                <icpPort/>
                <logging>
                <enable>
                <accessLog>1</accessLog>
                <storeLog>1</storeLog>
                </enable>
                <ignoreLogACL/>
                <target/>
                </logging>
                <alternateDNSservers/>
                <dnsV4First>0</dnsV4First>
                <forwardedForHandling>on</forwardedForHandling>
                <uriWhitespaceHandling>strip</uriWhitespaceHandling>
                <enablePinger>1</enablePinger>
                <useViaHeader>1</useViaHeader>
                <suppressVersion>0</suppressVersion>
                <connecttimeout/>
                <VisibleEmail>admin@localhost.local</VisibleEmail>
                <VisibleHostname>localhost</VisibleHostname>
                <cache>
                <local>
                <enabled>0</enabled>
                <directory>/var/squid/cache</directory>
                <cache_mem>256</cache_mem>
                <maximum_object_size/>
                <maximum_object_size_in_memory/>
                <memory_cache_mode>always</memory_cache_mode>
                <size>100</size>
                <l1>16</l1>
                <l2>256</l2>
                <cache_linux_packages>0</cache_linux_packages>
                <cache_windows_updates>0</cache_windows_updates>
                </local>
                </cache>
                <traffic>
                <enabled>0</enabled>
                <maxDownloadSize>2048</maxDownloadSize>
                <maxUploadSize>1024</maxUploadSize>
                <OverallBandwidthTrotteling>1024</OverallBandwidthTrotteling>
                <perHostTrotteling>256</perHostTrotteling>
                </traffic>
                <parentproxy>
                <enabled>0</enabled>
                <host/>
                <enableauth>0</enableauth>
                <user>username</user>
                <password>password</password>
                <port/>
                <localdomains/>
                <localips/>
                </parentproxy>
                </general>
                <forward>
                <interfaces>lan</interfaces>
                <port>3128</port>
                <sslbumpport>3129</sslbumpport>
                <sslbump>0</sslbump>
                <sslurlonly>0</sslurlonly>
                <sslcertificate/>
                <sslnobumpsites/>
                <ssl_crtd_storage_max_size>4</ssl_crtd_storage_max_size>
                <sslcrtd_children>5</sslcrtd_children>
                <snmp_enable>0</snmp_enable>
                <snmp_port>3401</snmp_port>
                <snmp_password>public</snmp_password>
                <ftpInterfaces/>
                <ftpPort>2121</ftpPort>
                <ftpTransparentMode>0</ftpTransparentMode>
                <addACLforInterfaceSubnets>1</addACLforInterfaceSubnets>
                <transparentMode>0</transparentMode>
                <acl>
                <allowedSubnets/>
                <unrestricted/>
                <bannedHosts/>
                <whiteList/>
                <blackList/>
                <browser/>
                <mimeType/>
                <googleapps/>
                <youtube/>
                <safePorts>80:http,21:ftp,443:https,70:gopher,210:wais,1025-65535:unregistered ports,280:http-mgmt,488:gss-http,591:filemaker,777:multiling http</safePorts>
                <sslPorts>443:https</sslPorts>
                <remoteACLs>
                <blacklists/>
                <UpdateCron/>
                </remoteACLs>
                </acl>
                <icap>
                <enable>0</enable>
                <RequestURL>icap://[::1]:1344/avscan</RequestURL>
                <ResponseURL>icap://[::1]:1344/avscan</ResponseURL>
                <SendClientIP>1</SendClientIP>
                <SendUsername>0</SendUsername>
                <EncodeUsername>0</EncodeUsername>
                <UsernameHeader>X-Username</UsernameHeader>
                <EnablePreview>1</EnablePreview>
                <PreviewSize>1024</PreviewSize>
                <OptionsTTL>60</OptionsTTL>
                <exclude/>
                </icap>
                <authentication>
                <method/>
                <authEnforceGroup/>
                <realm>OPNsense proxy authentication</realm>
                <credentialsttl>2</credentialsttl>
                <children>5</children>
                </authentication>
                </forward>
                <pac/>
                <error_pages>
                <template/>
                </error_pages>
                </proxy>
                <Syslog version="1.0.1">
                <general>
                <enabled>1</enabled>
                </general>
                <destinations/>
                </Syslog>
                <TrafficShaper version="1.0.3">
                <pipes/>
                <queues/>
                <rules/>
                </TrafficShaper>
                <IPsec version="1.0.1">
                <general>
                <enabled/>
                </general>
                <keyPairs/>
                <preSharedKeys/>
                </IPsec>
                <unboundplus version="1.0.8">
                <general>
                <enabled>1</enabled>
                <port>53</port>
                <stats/>
                <active_interface/>
                <dnssec>1</dnssec>
                <dns64/>
                <dns64prefix/>
                <noarecords/>
                <regdhcp/>
                <regdhcpdomain/>
                <regdhcpstatic/>
                <noreglladdr6/>
                <noregrecords/>
                <txtsupport/>
                <cacheflush/>
                <local_zone_type>transparent</local_zone_type>
                <outgoing_interface/>
                <enable_wpad/>
                </general>
                <advanced>
                <hideidentity/>
                <hideversion/>
                <prefetch/>
                <prefetchkey/>
                <dnssecstripped>1</dnssecstripped>
                <serveexpired/>
                <serveexpiredreplyttl/>
                <serveexpiredttl/>
                <serveexpiredttlreset/>
                <serveexpiredclienttimeout/>
                <qnameminstrict/>
                <extendedstatistics/>
                <logqueries/>
                <logreplies/>
                <logtagqueryreply/>
                <logservfail/>
                <loglocalactions/>
                <logverbosity>1</logverbosity>
                <valloglevel>0</valloglevel>
                <privatedomain/>
                <privateaddress>0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,169.254.0.0/16,172.16.0.0/12,192.0.2.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,::1/128,2001:db8::/32,fc00::/8,fd00::/8,fe80::/10</privateaddress>
                <insecuredomain/>
                <msgcachesize/>
                <rrsetcachesize/>
                <outgoingnumtcp/>
                <incomingnumtcp/>
                <numqueriesperthread/>
                <outgoingrange/>
                <jostletimeout/>
                <cachemaxttl/>
                <cachemaxnegativettl/>
                <cacheminttl/>
                <infrahostttl/>
                <infrakeepprobing/>
                <infracachenumhosts/>
                <unwantedreplythreshold/>
                </advanced>
                <acls>
                <default_action>allow</default_action>
                </acls>
                <dnsbl>
                <enabled>0</enabled>
                <safesearch/>
                <type/>
                <lists/>
                <whitelists/>
                <blocklists/>
                <wildcards/>
                <address/>
                <nxdomain/>
                </dnsbl>
                <forwarding>
                <enabled/>
                </forwarding>
                <dots/>
                <hosts/>
                <aliases/>
                <domains/>
                </unboundplus>
                <Swanctl version="1.0.0">
                <Connections/>
                <locals/>
                <remotes/>
                <children/>
                <Pools/>
                <VTIs/>
                <SPDs/>
                </Swanctl>
                <Kea>
                <ctrl_agent version="0.0.1">
                <general>
                <enabled>0</enabled>
                <http_host>127.0.0.1</http_host>
                <http_port>8000</http_port>
                </general>
                </ctrl_agent>
                <dhcp4 version="0.0.1">
                <general>
                <enabled>0</enabled>
                <interfaces/>
                <valid_lifetime>4000</valid_lifetime>
                </general>
                <ha>
                <enabled>0</enabled>
                <this_server_name/>
                </ha>
                <subnets/>
                <reservations/>
                <ha_peers/>
                </dhcp4>
                </Kea>
                <OpenVPN version="1.0.0">
                <Overwrites/>
                <Instances/>
                <StaticKeys/>
                </OpenVPN>
                <Gateways version="1.0.0">
                <gateway_item uuid="200ad045-5582-480c-93dd-af9eb4a0bc37">
                <disabled>1</disabled>
                <name>VAGRANT_DHCP</name>
                <descr>Interface VAGRANT_DHCP Gateway</descr>
                <interface>opt2</interface>
                <ipprotocol>inet</ipprotocol>
                <gateway/>
                <defaultgw>0</defaultgw>
                <fargw>0</fargw>
                <monitor_disable>1</monitor_disable>
                <monitor_noroute>0</monitor_noroute>
                <monitor/>
                <force_down>0</force_down>
                <priority>254</priority>
                <weight>1</weight>
                <latencylow/>
                <latencyhigh/>
                <losslow/>
                <losshigh/>
                <interval/>
                <time_period/>
                <loss_interval/>
                <data_length/>
                </gateway_item>
                </Gateways>
                <wireguard>
                <client version="0.0.7">
                <clients/>
                </client>
                <general version="0.0.1">
                <enabled>0</enabled>
                </general>
                <server version="0.0.4">
                <servers/>
                </server>
                </wireguard>
                </OPNsense>
                <cert>
                <refid>5a3951eaa0f49</refid>
                <descr>Web GUI SSL certificate</descr>
                <crt>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZiekNDQTFlZ0F3SUJBZ0lKQU9DSU5LLzhkbDBuTUEwR0NTcUdTSWIzRFFFQkN3VUFNRTR4Q3pBSkJnTlYKQkFZVEFrNU1NUlV3RXdZRFZRUUlEQXhhZFdsa0xVaHZiR3hoYm1ReEZUQVRCZ05WQkFjTURFMXBaR1JsYkdoaApjbTVwY3pFUk1BOEdBMVVFQ2d3SVQxQk9jMlZ1YzJVd0hoY05NVGN4TWpFNU1UYzFNalF6V2hjTk1UZ3hNakU1Ck1UYzFNalF6V2pCT01Rc3dDUVlEVlFRR0V3Sk9UREVWTUJNR0ExVUVDQXdNV25WcFpDMUliMnhzWVc1a01SVXcKRXdZRFZRUUhEQXhOYVdSa1pXeG9ZWEp1YVhNeEVUQVBCZ05WQkFvTUNFOVFUbk5sYm5ObE1JSUNJakFOQmdrcQpoa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQTdFVnRDQ3RnMUlEQ1plTTFDbTRWem1tTHlpRnoveUZtClVseXhRV2VIb0VGenVVQ0JlRkFodWNEUklRZ1hkTUFnbEUxY3dXZzVEdXhkOEtyeWFCYVNLSkFPdGdXRFgwOWoKOGZ5Z3hPZTRHd29MOGZTL0J2SVVFTkw0N1hiQUU3V015NmR2VVFjbkJmSWhYTXJDc25ScjQ1ZE95VzlyNHUrQQozR3lqOS9WR084NUlwN3dLZ2VuM3IxMisvMVN5SDNHaWV4emo4N3hIdnJqTE5TT1RqMUlzYzhyRVZHaFd1T3UyCmtvR2NoUHNjSzFnWE5UbkJxRnRIcVVXOUo3cUo3UGw5NkhrNGlGNkg5TnlpSGxpQWF3WGllaFcrOSs5ay9CQk8KWmpiWENlbjBxa3RVc3gzeFJXbVRsd2kwR1EvMllqV2dYSm8wM0Q3a3JrK01XTkoyR3hERmEvQjcvWGRsODdzawpTYncxemV6T2ZoNE1ZTFhaeExNRy9tRkU2V3B5cGN0MEVYRGd4UDdxcWtITWd2RmdpKzlrZmNGbHNQbGJxK05zCm1Nd0ovMEpoWjhyWWlDNlRsMUY3aWVzemMvd3FSN0NkSC9YN1RwY1hjSzA1aWRDTzA1KzNDS2lpUWpoUnh0NHUKTW5jcEhkVGJxNHRjTG1JTlFvQXlOUVNLK3huUnpQdmtQZTQvOGYzcUVsa0JrMVA0anFiVEJmR1F5bUFJTjZoRwo5QTd4cVJ5UE8rbEo3ZFRRangvdzg4QlNEbmVMRGtJcGxHRHZvVnpHSlBIVVV6cHJXNUtnYTdaNVJ6cEU0WFZWCkxhUGFtdUZnQVpUUVZIUkVnUG1jSmgySFU5SndDZHp2eG11WXlFWG5ueW5KODAxaktUcko0RlQxK2h6dmw3TjcKU2MwZlFrWm53eDhDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkRNdmZ2T1ZMdFpXUnh2MkF1SE04T3M1VlNMOApNQjhHQTFVZEl3UVlNQmFBRkRNdmZ2T1ZMdFpXUnh2MkF1SE04T3M1VlNMOE1Bd0dBMVVkRXdRRk1BTUJBZjh3CkRRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFOZEJscnJJcUdjckpZbThMUENVQ3p6UzF0TXBwNkpzdDZUanJSdGcKV1V6UXgzSHFMbVV2QjA5SWZuM2VXMmtwUnpybzV1Nm5EMEZIbDRTeHlHbXRhbHFBNGZCTld0OTQxOG1zTXdqZApUN2FPcmo4MkZuU1BCaTJNVmEwWmJONGp2RTNrZkRlT2pVWW9nQ0tkRkxTZG5UUjZEWjJhbVZaOWFERC9SdWtGCjdHVTMwVGFvb3k0UytxeUpmR2ViTDlxYUNBQ1ExUDg1UEw3OVNCNWJ2ZEM1VUZnTEtZcjdhbFY0TFZFOWhBYU0KY0wrZnFNNENvTTJHT1YyQWwvK0puamdzbmlZSDJqdFh3ZmNwNmhyaUcxZXNKNFpOUUFjelJjTEZzK1R3SVVBRApCNnlnTmk1SWQzQk5taWJaNmpWSyttZmlYZENzSDFQUXJxN0ZsTk5RSEdIMzVWMHlxUVVqMXJuUXIvSlVwanFaCno3a2ZqUWVCY2UwK1FRQVd0cVg3TjhzTFZQQ2RleWx5d3pkQnBDNEtsSHU1dXVZODJtN0lTWVY0TWpaMEFsMEYKY3U4bHdVeWs0K29rcE1rVk52QXJIRW1XZ2tDUWRpaXB1U1ZmT1pNc3BZQXZzdUhKdlBEL3dZMFRxRllzZ0lnNgpCVVNRa080dCtNdXZwVElIcDVGZTcrTktBUTNJczBZa1N5bDMzSzcyQmxtaGVlMm9nZy80TUwyRUZLeU92WWFBCmdvck5BTW9SdTNPRW01VUZzMDdJMW83RVVHYWRjQVlXRmZMZXlTV2wwRmRQV29kTHBkanYxQzVORjBXYVI2WjMKYjFjejNNa3JocXhUZzlEMnRWcVBBNFoyQjJXN1VOT08zTWJUV0ExRUJSZU5wVmlSb1Ywbk9HNTFpa1VtZERGRwprR1BnCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K</crt>
                <prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRZ0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1N3d2dna29BZ0VBQW9JQ0FRRHNSVzBJSzJEVWdNSmwKNHpVS2JoWE9hWXZLSVhQL0lXWlNYTEZCWjRlZ1FYTzVRSUY0VUNHNXdORWhDQmQwd0NDVVRWekJhRGtPN0YzdwpxdkpvRnBJb2tBNjJCWU5mVDJQeC9LREU1N2diQ2d2eDlMOEc4aFFRMHZqdGRzQVR0WXpMcDI5UkJ5Y0Y4aUZjCnlzS3lkR3ZqbDA3SmIydmk3NERjYktQMzlVWTd6a2ludkFxQjZmZXZYYjcvVkxJZmNhSjdIT1B6dkVlK3VNczEKSTVPUFVpeHp5c1JVYUZhNDY3YVNnWnlFK3h3cldCYzFPY0dvVzBlcFJiMG51b25zK1gzb2VUaUlYb2YwM0tJZQpXSUJyQmVKNkZiNzM3MlQ4RUU1bU50Y0o2ZlNxUzFTekhmRkZhWk9YQ0xRWkQvWmlOYUJjbWpUY1B1U3VUNHhZCjBuWWJFTVZyOEh2OWQyWHp1eVJKdkRYTjdNNStIZ3hndGRuRXN3YitZVVRwYW5LbHkzUVJjT0RFL3VxcVFjeUMKOFdDTDcyUjl3V1d3K1Z1cjQyeVl6QW4vUW1Gbnl0aUlMcE9YVVh1SjZ6TnovQ3BIc0owZjlmdE9seGR3clRtSgowSTdUbjdjSXFLSkNPRkhHM2k0eWR5a2QxTnVyaTF3dVlnMUNnREkxQklyN0dkSE0rK1E5N2oveC9lb1NXUUdUClUvaU9wdE1GOFpES1lBZzNxRWIwRHZHcEhJODc2VW50MU5DUEgvRHp3RklPZDRzT1FpbVVZTytoWE1ZazhkUlQKT210YmtxQnJ0bmxIT2tUaGRWVXRvOXFhNFdBQmxOQlVkRVNBK1p3bUhZZFQwbkFKM08vR2E1aklSZWVmS2NuegpUV01wT3NuZ1ZQWDZITytYczN0SnpSOUNSbWZESHdJREFRQUJBb0lDQUJNSjhTUkVZcFFkSUEwWHh2RmxONHFmCmhLMHdEdW5USml5aTNZRzR0dndaNmhwV2NWaGhsS1lrUEhYZDhnM3RZWEt4M1RTVWtteDZiWU4wTXY1aU96cmIKaU9Qd0E4c05XYTlwUFFkQTZOdjg3a044Qmx5bjZ5Z0Q2QjB5Z1gzVkZsaGUwS0NGNUFZZG9jU1piaUQxTXJCdgpRK0VGZ25zUjg1OVBmZE1BUjcyUC9OalBWVVZzdGhIQ2l4NkdFNmhtL3NITzdTdDUwNG94MStZYlRNdXl3blErCk5aM2Jub2xlTFNNWElLYXltVzJBdHJZS1JtbXJtVld4a2ZGK25aaWo3aHBxa2p5aTZXKzR5N09JVENqVG01RmMKNlR1UFplTE42Wk5nL2VrRm1qcVN3V3VCa1N5WHVsWGtWS2JrVzJWRWp2eUhUSlVtMkVTWGttYWg1dlI5WUhzUApqV2dsM2tldVl1QkxtQ3hHbzZhWEx1a2YvSVFGYTZ2akY2dE9BSWN1Zk0xZzNHKzBRTFl4QzRHL0J6K1pHcUlVCmY0MVQvVWd6WnJMc3NrdjBvbm9jeDZuTFE5QkNMdXRNYXVxYXVhK3UzTHd6dUVXMENkcmx5bU1OMmtEWU9pbFkKS0RqZHJqSzM4NzdUV0tmVjZ3VnhGWGZDK1pPbENvbG4xTHk1TnFlQ2tuL2g3N1dXVUhZNnVPb2lPTlA2L3FQZgpsbFJMaVBBeVFPTUduZDBuZWdVUzNZNjNLZjZpYkRHclB4UFMxb2FId2JZU2d4ZC8yUFViLzdlbGg1REFqekNLCjVJYnVoMzNlT0g4cklrelU2a1JsTjJZUlAwNFoxL1h5YXFrNkJRdjVrbFlYVm5tU0NHSEp5bTdHL21DaTdVZzMKT3RrcU9ueE9YaGVhQmowcUg0SXhBb0lCQVFENG9vNjJzRmFQeUNqemNuSm1iTU8wd2E4VUFPRGpwR2ltUmwzaQpKdFBYUXZIR3R5RCt2T2xPVm9tdURCNGdRWWpmeXRUR3NYc3k0YkgvNHpaR3E3T1VvYXY1bnRxUnk1L2tiaXNCCk0wSlZCeHE0bmZtVGVKeUlBZmt3c0NmQzJrZ2d3RkdFU0Z4SWt5VzR5bHFLc01GaUtVWjRNY3FEY25zaDFFSloKZUZENThiQVdha2VIaWozZnk2MkduV2dGN3g0UENhVklEd3luRG5UUDdTanA0QzZaVG1SOWJPRzRIblV2QVJaQQpaa3lkV2tRc1JGeHFCRWROMlRaOFhlY1BSaDlIb0ppVDdpWkJ6MVRSZkRxYzQ3cWVrazk3NTRycG05QlZMM082CmNKL0dkSGNuWGd6WE9TdHU3Zmp6N1QzQXB5TWF1dDVrd0x2VnhOM0RHcVorNG5HSkFvSUJBUUR6UlJ5U3U5YzEKLzF4dldlM2h6M2RIMGJ0dDVoTXNoWkhFVXJwZ053UGlFQkhkamt3VXRsWXJ3WFhlTmJhbXBlM01KZVdUY081ago2RXhpSDk2MEk0TjdOTDkyMm55Uk1MMDM5b2tJdDhueXoxREtqUnZNTy9FQmJaOXlTYXY4SVBwbE1leUtBVm1jClVrQUd4UDA5SW5abFhJM1RBa1NHVUdlQjh3d0k4cUhuazRVTVFiRllSTUVUQkZCa3YxY2MzR1lCN2lsUlR3Z0wKWllSMUJscWM0ck5NZGpOREY1U1ExMG4vcU1GeEp1dURXWkwraisyeDdGVWltNVY3dWtIWm1BRE9sUjJibXVyUgpmTU5kYkRGNllyY28zR0FyaVE2aDZQcmZWdmk4SDRGc1VTYnpXRFcyTzkxQXlXN0VjRnp4b2RYZ2MycjVOTExRCmRaeU93SW9kM3kxbkFvSUJBQjhHbWV4dUlMOGNhUS9IN2tLZHUrWW9iU0ovNFpCR2lkQ0Y0MTAvSHh3emZGd2gKcWZwZnRIVlVFeVltMlBPSmVmMERJSDRTMDU3THp4eHhTK3FScm4wVGw1UTBvRzJsRFRUQ0VwZTV2OE5BZWJNago4MnJWbUNMWXJESEpLWTBGRkE4U01KbmpOYkRRdTlwTlZmTU1qM1VpVldyV084RWZYZ0lnckk3aGxxazU0WkZLCmZkYUtCNktQbGYzQVVxUzY2L05RYnRHSkh6a1JjcjRuaC8xM1BobGZVT2JkMldUU1dDa2ZaNWx0cW8zUUg4V3UKV2lIWW10VTZEN1NCT3o0S3NBaU9IN3dGOGJ3d2xSTDIvNUZvVVhkTUpxTDloN1lTL1hKRDA1c21ScW5MQ3J0YwozeGxVUnZrMnRPUXJiSk5IeC9lajdmQ0FwRy9PZXlYSGc1TTl5cEVDZ2dFQVNHNW1jSVgvTVBPa1dQOGtwZHc0CnZxaUNydGtYRW1WK25qNm5nV2cvL3JvY0o2UnJvS3NkZ3crcUFZeHFvcm02ME5ManhQK1Y2eWRLUHRrUVhRQkoKOEpBbkJjTk4zWWp1ZmRBb3d2Qzk3MDZzMW5Jbk9hc0xPZ3Fpczh1ZHFvZERKb2d6em05U2VBbkJTSUswaDlSUAovaVFOa2lzVnJnd1lsWWVCS05UZFFlOFphU25TSE43endhN0NKUTBYYWQ5eGU5ZW1jN0FkVEE5ZzNkc1RkYXpHCkI5a1ZzRDlBRzlRT0UxSHlycmNRM2wzNE4xVXhSNDEvVjd1TlNYYU9qclFFWVgzaWYrY2pUVlpoY05wNjdONmgKZkVnSlZrMExqMGVvRW9GNXM4R0pybStITW1Nc011TW1JRmtaWXVHMXVyZ2R6eU51VVY3UWN1TGh4MXNxaEhSagp0d0tDQVFFQWtXYlZHTEpZM1FrSCt4WURYVEhqVnBIR0pLYmdZSmxoQXlUalIyNXVGTFppWkEyemFzRUdnVVhUCnFtc3RGc1VaRjU4di9UWGw1WTREazR0WGlsYkpqTnRmWmdxb05KOXM0Z0QvQklqd1psaUhNVzh1RlhYRHg0bUwKRVdmUEo4UUFQUjU4dUNhSU9BaldncGNkQTlYVzhaTzhrNGtSYTZoV0NVL3FObFVSRkJiRzJlZ1NQellJRzBGdAp6Y1REU2s3YUN2bjZ3d3F3bk8vRzJIQXNsazZvWVdzOU0xM3dueE90Qk9kMEhUMWhERW9qNnBzTG02MTFDMGNVCkYxNE1ZcmJ6K1ozeUxNWVlYZVU0bXd2dkRpRThjWXhiS3pOMW1kU3kwQnFyVFo3T1ExZktlZlREcnlKUnBjK0wKZkVWMHRSOXpicUZyRW1lNEpPZjU0aEhwcEZBT0lnPT0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=</prv>
                </cert>
                <ppps>
                <ppp/>
                </ppps>
                <virtualip version="1.0.0"/>
                <gateways> </gateways>
                <dhcpdv6/>
                <openvpn>
                <openvpn-server/>
                <openvpn-client/>
                </openvpn>
                <staticroutes version="1.0.0"/>
                <ifgroups version="1.0.0"/>
                <laggs version="1.0.0"/>
                <vlans version="1.0.0"/>
                </opnsense>
    """  # noqa: E501


@pytest.fixture(scope="function")
def sample_config_path(request):
    """
    Fixture that creates a temporary file with a test XML configuration.
    The file  is used in the tests.

    Returns:
    - str: The path to the temporary file.
    """
    with patch(
        "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",  # pylint: disable=line-too-long
        return_value="OPNsense Test",
    ), patch.dict(VERSION_MAP, TEST_VERSION_MAP, clear=True):
        # Create a temporary file with a name based on the test function
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(TEST_XML.encode())
            temp_file.flush()
            yield temp_file.name

    # Cleanup after the fixture is used
    os.unlink(temp_file.name)


def test_simple_interface_configuration_from_xml_to_etree():
    test_etree_opnsense: Element = ElementTree.fromstring(TEST_XML)

    test_etree_interface_configuration: Element = list(list(test_etree_opnsense)[4])[2]
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration.from_xml(
        test_etree_interface_configuration
    )
    assert test_interface_configuration.identifier == "opt1"
    assert test_interface_configuration.device == "em3"
    assert test_interface_configuration.descr == "DMZ"

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(test_etree_opnsense)[4])[2]

    assert xml_utils.elements_equal(
        test_interface_configuration.to_etree(), orig_test_interface_configuration
    )


def test_wan_interface_configuration_to_etree():
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration(
        identifier="wan",
        device="em2",
        descr="WAN",
        ipaddr="dhcp",
        dhcphostname=None,
        mtu=None,
        subnet=None,
        gateway=None,
        media=None,
        mediaopt=None,
        blockbogons=1,
        blockpriv=1,
        ipaddrv6="dhcp6",
        lock=1,
    )
    setattr(test_interface_configuration, "dhcp6-ia-pd-len", "0")

    test_element = test_interface_configuration.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(orig_etree)[4])[0]

    assert xml_utils.elements_equal(test_element, orig_test_interface_configuration)


def test_lan_interface_configuration_to_etree():
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration(
        identifier="lan",
        device="em1",
        enable=1,
        descr="LAN",
        ipaddr="192.168.56.10",
        spoofmac=None,
        subnet="21",
        blockbogons=1,
        ipaddrv6="track6",
        lock=1,
    )
    setattr(test_interface_configuration, "track6-interface", "wan")
    setattr(test_interface_configuration, "track6-prefix-id", "0")

    test_element = test_interface_configuration.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(orig_etree)[4])[1]

    assert xml_utils.elements_equal(test_element, orig_test_interface_configuration)


def test_opt1_interface_configuration_to_etree():
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration(
        identifier="opt1", device="em3", descr="DMZ", spoofmac=None, lock=1
    )
    test_element = test_interface_configuration.to_etree()
    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(orig_etree)[4])[2]

    assert xml_utils.elements_equal(test_element, orig_test_interface_configuration)


def test_opt2_interface_configuration_to_etree():
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration(
        identifier="opt2",
        device="em0",
        descr="VAGRANT",
        enable=1,
        spoofmac=None,
        lock=1,
        ipaddr="dhcp",
        dhcphostname=None,
        dhcprejectfrom=None,
        adv_dhcp_pt_timeout=None,
        adv_dhcp_pt_retry=None,
        adv_dhcp_pt_select_timeout=None,
        adv_dhcp_pt_reboot=None,
        adv_dhcp_pt_backoff_cutoff=None,
        adv_dhcp_pt_initial_interval=None,
        adv_dhcp_pt_values="SavedCfg",
        adv_dhcp_send_options=None,
        adv_dhcp_request_options=None,
        adv_dhcp_required_options=None,
        adv_dhcp_option_modifiers=None,
        adv_dhcp_config_advanced=None,
        adv_dhcp_config_file_override=None,
        adv_dhcp_config_file_override_path=None,
    )

    setattr(test_interface_configuration, "alias-address", None)
    setattr(test_interface_configuration, "alias-subnet", "32")

    test_element = test_interface_configuration.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(orig_etree)[4])[3]

    assert xml_utils.elements_equal(test_element, orig_test_interface_configuration)


def test_lo0_interface_configuration_to_etree():
    test_interface_configuration: InterfaceConfiguration = InterfaceConfiguration(
        internal_dynamic="1",
        identifier="lo0",
        device="lo0",
        descr="Loopback",
        enable=1,
        ipaddr="127.0.0.1",
        ipaddrv6="::1",
        subnet="8",
        subnetv6="128",
        type="none",
        virtual="1",
    )

    test_element = test_interface_configuration.to_etree()

    orig_etree: Element = ElementTree.fromstring(TEST_XML)
    orig_test_interface_configuration: Element = list(list(orig_etree)[4])[4]

    assert xml_utils.elements_equal(test_element, orig_test_interface_configuration)


def test_simple_interface_configuration_from_ansible_module_params_simple(
    sample_config_path,
):
    test_params: dict = {
        "identifier": "wan",
        "device": "vtnet1",
        "descr": "lan_interface",
    }
    test_interface_configuration: InterfaceConfiguration = (
        InterfaceConfiguration.from_ansible_module_params(test_params)
    )
    assert test_interface_configuration.identifier == "wan"
    assert test_interface_configuration.device == "vtnet1"
    assert test_interface_configuration.descr == "lan_interface"


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_description_update(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "lan",
        "device": "em1",
        "descr": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        test_interface_configuration: InterfaceConfiguration = (
            InterfaceConfiguration.from_ansible_module_params(test_params)
        )
        interfaces_set.update(test_interface_configuration)
        assert interfaces_set.changed

        interfaces_set.save()

    with InterfacesSet(sample_config_path) as new_interfaces_set:
        new_test_interface_configuration = new_interfaces_set.find(identifier="lan")
        assert new_test_interface_configuration.identifier == "lan"
        assert new_test_interface_configuration.device == "em1"
        assert new_test_interface_configuration.descr == "test_interface"
        new_interfaces_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em0", "em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_device_update(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "wan",
        "device": "em4",
        "descr": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        test_interface_configuration: InterfaceConfiguration = (
            InterfaceConfiguration.from_ansible_module_params(test_params)
        )
        interfaces_set.update(test_interface_configuration)
        assert interfaces_set.changed
        interfaces_set.save()

    with InterfacesSet(sample_config_path) as new_interfaces_set:
        new_test_interface_configuration = new_interfaces_set.find(identifier="wan")
        assert new_test_interface_configuration.identifier == "wan"
        assert new_test_interface_configuration.device == "em4"
        assert new_test_interface_configuration.descr == "test_interface"
        new_interfaces_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em0", "em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_not_existing_device(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "wan",
        "device": "test",
        "descr": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseInterfaceNotFoundError) as excinfo:
            test_interface_configuration: InterfaceConfiguration = (
                InterfaceConfiguration.from_ansible_module_params(test_params)
            )
            interfaces_set.update(test_interface_configuration)
            interfaces_set.save()
        assert "Interface was not found on OPNsense Instance!" in str(excinfo.value)


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em0", "em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_not_existing_identifier_and_used_device(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "test",
        "device": "em0",
        "descr": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseDeviceAlreadyAssignedError) as excinfo:
            test_interface_configuration: InterfaceConfiguration = (
                InterfaceConfiguration.from_ansible_module_params(test_params)
            )
            interfaces_set.update(test_interface_configuration)
            interfaces_set.save()
        assert (
            "This device is already assigned, please unassign this device first"
            in str(excinfo.value)
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em0", "em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_not_existing_identifier_and_not_used_device(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "test",
        "device": "em4",
        "descr": "test_interface",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        test_interface_configuration: InterfaceConfiguration = (
            InterfaceConfiguration.from_ansible_module_params(test_params)
        )
        interfaces_set.update(test_interface_configuration)
        assert interfaces_set.changed
        interfaces_set.save()

    with InterfacesSet(sample_config_path) as new_interfaces_set:
        new_test_interface_configuration = new_interfaces_set.find(identifier="test")
        assert new_test_interface_configuration.identifier == "test"
        assert new_test_interface_configuration.device == "em4"
        assert new_test_interface_configuration.descr == "test_interface"
        new_interfaces_set.save()


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.InterfacesSet.get_interfaces",
    return_value=["em0", "em1", "em2", "em3", "em4"],
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_interface_configuration_from_ansible_module_params_with_duplicate_device(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    test_params: dict = {
        "identifier": "wan",
        "device": "em1",
        "descr": "duplicate device",
    }
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseDeviceAlreadyAssignedError) as excinfo:
            test_interface_configuration: InterfaceConfiguration = (
                InterfaceConfiguration.from_ansible_module_params(test_params)
            )
            interfaces_set.update(test_interface_configuration)
            interfaces_set.save()
        assert (
            "This device is already assigned, please unassign this device first"
            in str(excinfo.value)
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.opnsense_utils.run_command",
    return_value={"stdout": "em0,em1,em2", "stderr": None},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_get_interfaces_success(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    # Assuming InterfacesSet needs a configuration path and we have sample_config_path defined
    with InterfacesSet(sample_config_path) as interfaces_set:
        result = interfaces_set.get_interfaces()

        assert result == ["em0", "em1", "em2"]


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.opnsense_utils.run_command",
    return_value={"stdout": "", "stderr": None},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_get_interfaces_success(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    # Assuming InterfacesSet needs a configuration path and we have sample_config_path defined
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseGetInterfacesError) as excinfo:
            result = interfaces_set.get_interfaces()
        assert (
            "error encounterd while getting interfaces, less than one interface available"
            in str(excinfo.value)
        )


@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.version_utils.get_opnsense_version",
    return_value="OPNsense Test",
)
@patch(
    "ansible_collections.puzzle.opnsense.plugins.module_utils.interfaces_configuration_utils.opnsense_utils.run_command",
    return_value={"stdout": "", "stderr": "there was an error"},
)
@patch.dict(in_dict=VERSION_MAP, values=TEST_VERSION_MAP, clear=True)
def test_get_interfaces_success(
    mock_get_version, mock_get_interfaces, sample_config_path
):
    # Assuming InterfacesSet needs a configuration path and we have sample_config_path defined
    with InterfacesSet(sample_config_path) as interfaces_set:
        with pytest.raises(OPNSenseGetInterfacesError) as excinfo:
            result = interfaces_set.get_interfaces()
        assert "error encounterd while getting interfaces" in str(excinfo.value)
