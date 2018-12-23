import time
import datetime
import pyshark
import glob
import os
import platform
from threading import Thread
from builtins import print
import pandas as pd
import warnings
import sys
import predict

if not sys.warnoptions:
    warnings.simplefilter("ignore")

class Protocol:
    protocol = {
        "tcp" : "1",
        "icmp" : "1",
        "udp" : "1",
    }

class Service:

    service = {
        "1/tcp": "tcpmux",
        "7/tcp": "echo",
        "7/udp": "echo",
        "9/tcp": "discard",
        "9/udp": "discard",
        "11/tcp": "systat",
        "13/tcp": "daytime",
        "13/udp": "daytime",
        "15/tcp": "netstat",
        "17/tcp": "qotd",
        "18/tcp": "msp",
        "18/udp": "msp",
        "19/tcp": "chargen",
        "19/udp": "chargen",
        "20/tcp": "ftp-data",
        "21/tcp": "ftp",
        "21/udp": "fsp",
        "22/tcp": "ssh",
        "22/udp": "ssh",
        "23/tcp": "telnet",
        "25/tcp": "smtp",
        "37/tcp": "time",
        "37/udp": "time",
        "39/udp": "rlp",
        "42/tcp": "nameserver",
        "43/tcp": "whois",
        "49/tcp": "tacacs",
        "49/udp": "tacacs",
        "50/tcp": "re-mail-ck",
        "50/udp": "re-mail-ck",
        "53/tcp": "domain",
        "53/udp": "domain",
        "57/tcp": "mtp",
        "65/tcp": "tacacs-ds",
        "65/udp": "tacacs-ds",
        "67/tcp": "bootps",
        "67/udp": "bootps",
        "68/tcp": "bootpc",
        "68/udp": "bootpc",
        "69/udp": "tftp",
        "70/tcp": "gopher",
        "70/udp": "gopher",
        "77/tcp": "rje",
        "79/tcp": "finger",
        "80/tcp": "http",
        "80/udp": "http",
        "87/tcp": "link",
        "88/tcp": "kerberos",
        "88/udp": "kerberos",
        "95/tcp": "supdup",
        "101/tcp": "hostnames",
        "102/tcp": "iso-tsap",
        "104/tcp": "acr-nema",
        "104/udp": "acr-nema",
        "105/tcp": "csnet-ns",
        "105/udp": "csnet-ns",
        "107/tcp": "rtelnet",
        "107/udp": "rtelnet",
        "109/tcp": "pop2",
        "109/udp": "pop2",
        "110/tcp": "pop3",
        "110/udp": "pop3",
        "111/tcp": "sunrpc",
        "111/udp": "sunrpc",
        "113/tcp": "auth",
        "115/tcp": "sftp",
        "117/tcp": "uucp-path",
        "119/tcp": "nntp",
        "123/tcp": "ntp",
        "123/udp": "ntp",
        "129/tcp": "pwdgen",
        "129/udp": "pwdgen",
        "135/tcp": "loc-srv",
        "135/udp": "loc-srv",
        "137/tcp": "netbios-ns",
        "137/udp": "netbios-ns",
        "138/tcp": "netbios-dgm",
        "138/udp": "netbios-dgm",
        "139/tcp": "netbios-ssn",
        "139/udp": "netbios-ssn",
        "143/tcp": "imap2",
        "143/udp": "imap2",
        "161/tcp": "snmp",
        "161/udp": "snmp",
        "162/tcp": "snmp-trap",
        "162/udp": "snmp-trap",
        "163/tcp": "cmip-man",
        "163/udp": "cmip-man",
        "164/tcp": "cmip-agent",
        "164/udp": "cmip-agent",
        "174/tcp": "mailq",
        "174/udp": "mailq",
        "177/tcp": "xdmcp",
        "177/udp": "xdmcp",
        "178/tcp": "nextstep",
        "178/udp": "nextstep",
        "179/tcp": "bgp",
        "179/udp": "bgp",
        "191/tcp": "prospero",
        "191/udp": "prospero",
        "194/tcp": "irc",
        "194/udp": "irc",
        "199/tcp": "smux",
        "199/udp": "smux",
        "201/tcp": "at-rtmp",
        "201/udp": "at-rtmp",
        "202/tcp": "at-nbp",
        "202/udp": "at-nbp",
        "204/tcp": "at-echo",
        "204/udp": "at-echo",
        "206/tcp": "at-zis",
        "206/udp": "at-zis",
        "209/tcp": "qmtp",
        "209/udp": "qmtp",
        "210/tcp": "z3950",
        "210/udp": "z3950",
        "213/tcp": "ipx",
        "213/udp": "ipx",
        "220/tcp": "imap3",
        "220/udp": "imap3",
        "345/tcp": "pawserv",
        "345/udp": "pawserv",
        "346/tcp": "zserv",
        "346/udp": "zserv",
        "347/tcp": "fatserv",
        "347/udp": "fatserv",
        "369/tcp": "rpc2portmap",
        "369/udp": "rpc2portmap",
        "370/tcp": "codaauth2",
        "370/udp": "codaauth2",
        "371/tcp": "clearcase",
        "371/udp": "clearcase",
        "372/tcp": "ulistserv",
        "372/udp": "ulistserv",
        "389/tcp": "ldap",
        "389/udp": "ldap",
        "406/tcp": "imsp",
        "406/udp": "imsp",
        "427/tcp": "svrloc",
        "427/udp": "svrloc",
        "443/tcp": "https",
        "443/udp": "https",
        "444/tcp": "snpp",
        "444/udp": "snpp",
        "445/tcp": "microsoft-ds",
        "445/udp": "microsoft-ds",
        "464/tcp": "kpasswd",
        "464/udp": "kpasswd",
        "487/tcp": "saft",
        "487/udp": "saft",
        "500/tcp": "isakmp",
        "500/udp": "isakmp",
        "554/tcp": "rtsp",
        "554/udp": "rtsp",
        "607/tcp": "nqs",
        "607/udp": "nqs",
        "610/tcp": "npmp-local",
        "610/udp": "npmp-local",
        "611/tcp": "npmp-gui",
        "611/udp": "npmp-gui",
        "612/tcp": "hmmp-ind",
        "612/udp": "hmmp-ind",
        "628/tcp": "qmqp",
        "628/udp": "qmqp",
        "631/tcp": "ipp",
        "631/udp": "ipp",
        "512/tcp": "exec",
        "512/udp": "biff",
        "513/tcp": "login",
        "513/udp": "who",
        "514/tcp": "shell",
        "514/udp": "syslog",
        "515/tcp": "printer",
        "517/udp": "talk",
        "518/udp": "ntalk",
        "520/udp": "route",
        "525/udp": "timed",
        "526/tcp": "tempo",
        "530/tcp": "courier",
        "531/tcp": "conference",
        "532/tcp": "netnews",
        "533/udp": "netwall",
        "538/tcp": "gdomap",
        "538/udp": "gdomap",
        "540/tcp": "uucp",
        "543/tcp": "klogin",
        "544/tcp": "kshell",
        "546/tcp": "dhcpv6-client",
        "546/udp": "dhcpv6-client",
        "547/tcp": "dhcpv6-server",
        "547/udp": "dhcpv6-server",
        "548/tcp": "afpovertcp",
        "548/udp": "afpovertcp",
        "549/tcp": "idfp",
        "549/udp": "idfp",
        "556/tcp": "remotefs",
        "563/tcp": "nntps",
        "563/udp": "nntps",
        "587/tcp": "submission",
        "587/udp": "submission",
        "636/tcp": "ldaps",
        "636/udp": "ldaps",
        "655/tcp": "tinc",
        "655/udp": "tinc",
        "706/tcp": "silc",
        "706/udp": "silc",
        "749/tcp": "kerberos-adm",
        "765/tcp": "webster",
        "765/udp": "webster",
        "873/tcp": "rsync",
        "873/udp": "rsync",
        "989/tcp": "ftps-data",
        "990/tcp": "ftps",
        "992/tcp": "telnets",
        "992/udp": "telnets",
        "993/tcp": "imaps",
        "993/udp": "imaps",
        "994/tcp": "ircs",
        "994/udp": "ircs",
        "995/tcp": "pop3s",
        "995/udp": "pop3s",
        "1080/tcp": "socks",
        "1080/udp": "socks",
        "1093/tcp": "proofd",
        "1093/udp": "proofd",
        "1094/tcp": "rootd",
        "1094/udp": "rootd",
        "1194/tcp": "openvpn",
        "1194/udp": "openvpn",
        "1099/tcp": "rmiregistry",
        "1099/udp": "rmiregistry",
        "1214/tcp": "kazaa",
        "1214/udp": "kazaa",
        "1241/tcp": "nessus",
        "1241/udp": "nessus",
        "1352/tcp": "lotusnote",
        "1352/udp": "lotusnote",
        "1433/tcp": "ms-sql-s",
        "1433/udp": "ms-sql-s",
        "1434/tcp": "ms-sql-m",
        "1434/udp": "ms-sql-m",
        "1524/tcp": "ingreslock",
        "1524/udp": "ingreslock",
        "1525/tcp": "prospero-np",
        "1525/udp": "prospero-np",
        "1645/tcp": "datametrics",
        "1645/udp": "datametrics",
        "1646/tcp": "sa-msg-port",
        "1646/udp": "sa-msg-port",
        "1649/tcp": "kermit",
        "1649/udp": "kermit",
        "1677/tcp": "groupwise",
        "1677/udp": "groupwise",
        "1701/tcp": "l2f",
        "1701/udp": "l2f",
        "1812/tcp": "radius",
        "1812/udp": "radius",
        "1813/tcp": "radius-acct",
        "1813/udp": "radius-acct",
        "1863/tcp": "msnp",
        "1863/udp": "msnp",
        "1957/tcp": "unix-status",
        "1958/tcp": "log-server",
        "1959/tcp": "remoteping",
        "2000/tcp": "cisco-sccp",
        "2000/udp": "cisco-sccp",
        "2010/tcp": "search",
        "2010/tcp": "pipe-server",
        "2049/tcp": "nfs",
        "2049/udp": "nfs",
        "2086/tcp": "gnunet",
        "2086/udp": "gnunet",
        "2101/tcp": "rtcm-sc104",
        "2101/udp": "rtcm-sc104",
        "2119/tcp": "gsigatekeeper",
        "2119/udp": "gsigatekeeper",
        "2135/tcp": "gris",
        "2135/udp": "gris",
        "2401/tcp": "cvspserver",
        "2401/udp": "cvspserver",
        "2430/tcp": "venus",
        "2430/udp": "venus",
        "2431/tcp": "venus-se",
        "2431/udp": "venus-se",
        "2432/tcp": "codasrv",
        "2432/udp": "codasrv",
        "2433/tcp": "codasrv-se",
        "2433/udp": "codasrv-se",
        "2583/tcp": "mon",
        "2583/udp": "mon",
        "2628/tcp": "dict",
        "2628/udp": "dict",
        "2792/tcp": "f5-globalsite",
        "2792/udp": "f5-globalsite",
        "2811/tcp": "gsiftp",
        "2811/udp": "gsiftp",
        "2947/tcp": "gpsd",
        "2947/udp": "gpsd",
        "3050/tcp": "gds-db",
        "3050/udp": "gds-db",
        "3130/tcp": "icpv2",
        "3130/udp": "icpv2",
        "3306/tcp": "mysql",
        "3306/udp": "mysql",
        "3493/tcp": "nut",
        "3493/udp": "nut",
        "3632/tcp": "distcc",
        "3632/udp": "distcc",
        "3689/tcp": "daap",
        "3689/udp": "daap",
        "3690/tcp": "svn",
        "3690/udp": "svn",
        "4031/tcp": "suucp",
        "4031/udp": "suucp",
        "4094/tcp": "sysrqd",
        "4094/udp": "sysrqd",
        "4190/tcp": "sieve",
        "4369/tcp": "epmd",
        "4369/udp": "epmd",
        "4373/tcp": "remctl",
        "4373/udp": "remctl",
        "4353/tcp": "f5-iquery",
        "4353/udp": "f5-iquery",
        "4569/tcp": "iax",
        "4569/udp": "iax",
        "4691/tcp": "mtn",
        "4691/udp": "mtn",
        "4899/tcp": "radmin-port",
        "4899/udp": "radmin-port",
        "5002/udp": "rfe",
        "5002/tcp": "rfe",
        "5050/tcp": "mmcc",
        "5050/udp": "mmcc",
        "5060/tcp": "sip",
        "5060/udp": "sip",
        "5061/tcp": "sip-tls",
        "5061/udp": "sip-tls",
        "5190/tcp": "aol",
        "5190/udp": "aol",
        "5222/tcp": "xmpp-client",
        "5222/udp": "xmpp-client",
        "5269/tcp": "xmpp-server",
        "5269/udp": "xmpp-server",
        "5308/tcp": "cfengine",
        "5308/udp": "cfengine",
        "5353/tcp": "mdns",
        "5353/udp": "mdns",
        "5432/tcp": "postgresql",
        "5432/udp": "postgresql",
        "5556/tcp": "freeciv",
        "5556/udp": "freeciv",
        "5672/tcp": "amqp",
        "5672/udp": "amqp",
        "5672/sctp": "amqp",
        "5688/tcp": "ggz",
        "5688/udp": "ggz",
        "6000/tcp": "x11",
        "6000/udp": "x11",
        "6001/tcp": "x11-1",
        "6001/udp": "x11-1",
        "6002/tcp": "x11-2",
        "6002/udp": "x11-2",
        "6003/tcp": "x11-3",
        "6003/udp": "x11-3",
        "6004/tcp": "x11-4",
        "6004/udp": "x11-4",
        "6005/tcp": "x11-5",
        "6005/udp": "x11-5",
        "6006/tcp": "x11-6",
        "6006/udp": "x11-6",
        "6007/tcp": "x11-7",
        "6007/udp": "x11-7",
        "6346/tcp": "gnutella-svc",
        "6346/udp": "gnutella-svc",
        "6347/tcp": "gnutella-rtr",
        "6347/udp": "gnutella-rtr",
        "6444/tcp": "sge-qmaster",
        "6444/udp": "sge-qmaster",
        "6445/tcp": "sge-execd",
        "6445/udp": "sge-execd",
        "6446/tcp": "mysql-proxy",
        "6446/udp": "mysql-proxy",
        "7000/tcp": "afs3-fileserver",
        "7000/udp": "afs3-fileserver",
        "7001/tcp": "afs3-callback",
        "7001/udp": "afs3-callback",
        "7002/tcp": "afs3-prserver",
        "7002/udp": "afs3-prserver",
        "7003/tcp": "afs3-vlserver",
        "7003/udp": "afs3-vlserver",
        "7004/tcp": "afs3-kaserver",
        "7004/udp": "afs3-kaserver",
        "7005/tcp": "afs3-volser",
        "7005/udp": "afs3-volser",
        "7006/tcp": "afs3-errors",
        "7006/udp": "afs3-errors",
        "7007/tcp": "afs3-bos",
        "7007/udp": "afs3-bos",
        "7008/tcp": "afs3-update",
        "7008/udp": "afs3-update",
        "7009/tcp": "afs3-rmtsys",
        "7009/udp": "afs3-rmtsys",
        "7100/tcp": "font-service",
        "7100/udp": "font-service",
        "8080/tcp": "http-alt",
        "8080/udp": "http-alt",
        "9101/tcp": "bacula-dir",
        "9101/udp": "bacula-dir",
        "9102/tcp": "bacula-fd",
        "9102/udp": "bacula-fd",
        "9103/tcp": "bacula-sd",
        "9103/udp": "bacula-sd",
        "9667/tcp": "xmms2",
        "9667/udp": "xmms2",
        "10809/tcp": "nbd",
        "10050/tcp": "zabbix-agent",
        "10050/udp": "zabbix-agent",
        "10051/tcp": "zabbix-trapper",
        "10051/udp": "zabbix-trapper",
        "10080/tcp": "amanda",
        "10080/udp": "amanda",
        "11371/tcp": "hkp",
        "11371/udp": "hkp",
        "13720/tcp": "bprd",
        "13720/udp": "bprd",
        "13721/tcp": "bpdbm",
        "13721/udp": "bpdbm",
        "13722/tcp": "bpjava-msvc",
        "13722/udp": "bpjava-msvc",
        "13724/tcp": "vnetd",
        "13724/udp": "vnetd",
        "13782/tcp": "bpcd",
        "13782/udp": "bpcd",
        "13783/tcp": "vopied",
        "13783/udp": "vopied",
        "22125/tcp": "dcap",
        "22128/tcp": "gsidcap",
        "22273/tcp": "wnn6",
        "22273/udp": "wnn6",
        "1/ddp": "rtmp",
        "2/ddp": "nbp",
        "4/ddp": "echo",
        "6/ddp": "zip",
        "750/udp": "kerberos4",
        "750/tcp": "kerberos4",
        "751/udp": "kerberos-master",
        "751/tcp": "kerberos-master",
        "752/udp": "passwd-server",
        "754/tcp": "krb-prop",
        "760/tcp": "krbupdate",
        "901/tcp": "swat",
        "1109/tcp": "kpop",
        "2053/tcp": "knetd",
        "2102/udp": "zephyr-srv",
        "2103/udp": "zephyr-clt",
        "2104/udp": "zephyr-hm",
        "2105/tcp": "eklogin",
        "98/tcp": "linuxconf",
        "106/tcp": "poppassd",
        "106/udp": "poppassd",
        "465/tcp": "ssmtp",
        "775/tcp": "moira-db",
        "777/tcp": "moira-update",
        "779/udp": "moira-ureg",
        "783/tcp": "spamd",
        "808/tcp": "omirr",
        "808/udp": "omirr",
        "1001/tcp": "customs",
        "1001/udp": "customs",
        "1178/tcp": "skkserv",
        "1210/udp": "predict",
        "1236/tcp": "rmtcfg",
        "1300/tcp": "wipld",
        "1313/tcp": "xtel",
        "1314/tcp": "xtelw",
        "1529/tcp": "support",
        "2003/tcp": "cfinger",
        "2121/tcp": "frox",
        "2150/tcp": "ninstall",
        "2150/udp": "ninstall",
        "2600/tcp": "zebrasrv",
        "2601/tcp": "zebra",
        "2602/tcp": "ripd",
        "2603/tcp": "ripngd",
        "2604/tcp": "ospfd",
        "2605/tcp": "bgpd",
        "2606/tcp": "ospf6d",
        "2607/tcp": "ospfapi",
        "2608/tcp": "isisd",
        "2988/tcp": "afbackup",
        "2988/udp": "afbackup",
        "2989/tcp": "afmbackup",
        "2989/udp": "afmbackup",
        "4224/tcp": "xtell",
        "4557/tcp": "fax",
        "4559/tcp": "hylafax",
        "4600/tcp": "distmp3",
        "4949/tcp": "munin",
        "5051/tcp": "enbd-cstatd",
        "5052/tcp": "enbd-sstatd",
        "5151/tcp": "pcrd",
        "5354/tcp": "noclog",
        "5354/udp": "noclog",
        "5355/tcp": "hostmon",
        "5355/udp": "hostmon",
        "5555/udp": "rplay",
        "5666/tcp": "nrpe",
        "5667/tcp": "nsca",
        "5674/tcp": "mrtd",
        "5675/tcp": "bgpsim",
        "5680/tcp": "canna",
        "6566/tcp": "sane-port",
        "6667/tcp": "ircd",
        "8021/tcp": "zope-ftp",
        "8081/tcp": "tproxy",
        "8088/tcp": "omniorb",
        "8088/udp": "omniorb",
        "8990/tcp": "clc-build-daemon",
        "9098/tcp": "xinetd",
        "9359/udp": "mandelspawn",
        "9418/tcp": "git",
        "9673/tcp": "zope",
        "10000/tcp": "webmin",
        "10081/tcp": "kamanda",
        "10081/udp": "kamanda",
        "10082/tcp": "amandaidx",
        "10083/tcp": "amidxtape",
        "11201/tcp": "smsqp",
        "11201/udp": "smsqp",
        "15345/tcp": "xpilot",
        "15345/udp": "xpilot",
        "17001/udp": "sgi-cmsd",
        "17002/udp": "sgi-crsd",
        "17003/udp": "sgi-gcd",
        "17004/tcp": "sgi-cad",
        "20011/tcp": "isdnlog",
        "20011/udp": "isdnlog",
        "20012/tcp": "vboxd",
        "20012/udp": "vboxd",
        "24554/tcp": "binkp",
        "27374/tcp": "asp",
        "27374/udp": "asp",
        "30865/tcp": "csync2",
        "57000/tcp": "dircproxy",
        "60177/tcp": "tfido",
        "60179/tcp": "fido"

    }


class Packet(object):
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, service, flag, sequence_number, acknowledgment_number):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.service = service
        self.flag = flag
        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number


class PacketStt(object):
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, service, flag, sequence_number, acknowledgment_number, status_conn):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.service = service
        self.flag = flag
        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number
        self.status_conn = status_conn


class HandlePcap:

    # Return "" if value equal None
    def cvNonetoStr(self, var):
        if var == None:
            return ""
        else:
            return var

    # Check has attribute
    def check_hasattr(self, parent, child):
        if hasattr(parent, child):
            return True;
        return False;

    def is_connection_success(self, index, packet, packetList):
        if packet.flag == 'syn':
            sequence_number = int(packet.sequence_number)
            src_ip = packet.src_ip
            dst_ip = packet.dst_ip
            for index, pkt in enumerate(packetList):
                index_1 = index
                if pkt.src_ip == dst_ip and pkt.flag == "synack" and int(pkt.acknowledgment_number) == sequence_number+1:
                    sequence_number_ser = int(pkt.sequence_number)
                    acknowledgment_number_ser = int(pkt.acknowledgment_number)
                    for index_1, pkt_1 in enumerate(packetList):
                        if pkt_1.src_ip == src_ip and pkt_1.dst_ip == dst_ip and pkt_1.flag == "ack" \
                                and int(pkt_1.sequence_number) == acknowledgment_number_ser \
                                and int(pkt_1.acknowledgment_number) == sequence_number_ser+1:
                            return "True"
                index_1 += 1
        return "False"


    # 1- Get Source ip
    def get_src_ip(self, packet):
        src_ip = 0
        if self.check_hasattr(packet, "ip"):
            src_ip = packet.ip.src_host
        return str(src_ip)

    # 2- Get Destination ip
    def get_dst_ip(self, packet):
        dst_ip = 0
        if self.check_hasattr(packet, "ip"):
            dst_ip = packet.ip.dst_host
        return str(dst_ip)

    # 3 - Get Source port
    def get_src_port(self, packet, protocol):
        src_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "srcport"):
                src_port = packet[protocol].srcport
        return str(src_port)

    # 4 - Get Destination port
    def get_dst_port(self, packet, protocol):
        dst_port = 0
        if self.check_hasattr(packet, protocol):
            if self.check_hasattr(packet[protocol], "dstport"):
                dst_port = packet[protocol].dstport
        return str(dst_port)

    # 5- Get protocol
    def get_protocol(self, packet):
        protocol = "other"
        protocolDic = Protocol.protocol
        if self.check_hasattr(packet, "frame_info"):
            split = str(packet.frame_info.protocols).split(":")
            i = 0
            while i < len(split):
                protocol = protocolDic.get(split[i])
                if protocol != None:
                    protocol = split[i]
                    break
                i += 1
            if protocol == None:
                protocol = "other"
        return protocol

    # Get flag TCP
    def get_flag(self, packet, protocol):
        flag = ""
        if protocol == "tcp":
            if int(packet.tcp.flags_syn) != 0:
                flag += "syn"
            if int(packet.tcp.flags_ack) != 0:
                flag += "ack"
            if int(packet.tcp.flags_cwr) != 0:
                flag += "cwr"
            if int(packet.tcp.flags_ecn) != 0:
                flag += "ecn"
            if int(packet.tcp.flags_fin) != 0:
                flag += "fin"
            if int(packet.tcp.flags_ns) != 0:
                flag += "ns"
            if int(packet.tcp.flags_push) != 0:
                flag += "push"
            if int(packet.tcp.flags_res) != 0:
                flag += "res"
            if int(packet.tcp.flags_reset) != 0:
                flag += "reset"
            if int(packet.tcp.flags_urg) != 0:
                flag += "urg"
        return flag

    # Get sequence number
    def get_seq_number(self, packet, protocol):
        seq_number = 0
        if protocol == "tcp":
            seq_number = packet.tcp.seq
        return seq_number

    # Get acknowledgment number
    def get_ackn_number(self, packet, protocol):
        ackn_number = 0
        if protocol == "tcp":
            ackn_number = packet.tcp.ack
        return ackn_number

    def get_frame_len(self, packet):
        if int(packet.frame_info.len) != 0:
            return int(packet.frame_info.len)
        else:
            return 0

    # Get service
    def get_service_http(self, protocol, port):
        if Service.service.get(port + "/" + protocol) != None:
            service_http = Service.service.get(port + "/" + protocol)
        else:
            service_http = "other"
        return service_http

    def get_count(self, packetList, packet):
        count = 0
        for pkt in packetList:
            if packet.src_ip == pkt.src_ip and pkt.dst_ip == packet.dst_ip:
                count += 1
        return count

    def get_srv_count(self, packetList, packet):
        srv_count = 0
        for pkt in packetList:
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and packet.dst_port == pkt.dst_port:
                srv_count += 1
        return srv_count

    def get_serror_rate(self, packetList, packet):
        serror_rate = 0
        for pkt in packetList:
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and pkt.status_conn == False:
                serror_rate += 1
        return serror_rate

    def get_srv_serror_rate(self, packetList, packet):
        srv_serror_rate = 0
        for pkt in packetList:
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and packet.dst_port == pkt.dst_port and pkt.status_conn == False:
                srv_serror_rate += 1
        return srv_serror_rate

    def get_same_srv_rate(self, srv_count, count):
        same_srv_rate = srv_count/count
        return same_srv_rate

    def get_dst_host_count(self, packetList, packet):
        dst_host_count = 0
        for pkt in packetList:
            if pkt.dst_ip == packet.dst_ip:
                dst_host_count += 1
        return dst_host_count

    def get_dst_host_srv_count(self, packetList, packet):
        dst_host_srv_count = 0
        for pkt in packetList:
            if pkt.dst_port == packet.dst_port:
                dst_host_srv_count += 1
        return dst_host_srv_count

    def get_dst_host_same_srv_rate(self, packetList, packet):
        dst_host_same_srv_rate = 0
        for pkt in packetList:
            if pkt.dst_ip == packet.dst_ip and pkt.dst_port == packet.dst_port:
                dst_host_same_srv_rate += 1
        return dst_host_same_srv_rate

    def get_dst_host_serror_rate(self, packetList, packet):
        dst_host_serror_rate = 0
        for pkt in packetList:
            if pkt.dst_ip == packet.dst_ip and pkt.status_conn == False:
                dst_host_serror_rate += 1
        return dst_host_serror_rate

    def get_dst_host_srv_serror_rate(self, packetList, packet):
        dst_host_srv_serror_rate = 0
        for pkt in packetList:
            if pkt.dst_port == packet.dst_port and pkt.status_conn == False:
                dst_host_srv_serror_rate += 1
        return dst_host_srv_serror_rate

    def get_flag_S0(self, packet):
        if packet.status_conn == False:
            flag_S0 = 1
        else:
            flag_S0 = 0
        return flag_S0

    def get_flag_SF(self, packet):
        if packet.status_conn == True:
            flag_SF = 1
        else:
            flag_SF = 0
        return flag_SF



    # Get count
    # Get srv_count
    # Get serror_rate
    # Get srv_serror_rate
    # Get dst_host_count
    # Get dst_host_srv_count
    # Get dst_host_same_srv_rate
    # Get dst_host_serror_rate
    # Get dst_host_srv_serror_rate
    def get_calculate_feature(self, packet, packetList):
        count = 0
        srv_count = 0
        serror_rate = 0
        srv_serror_rate = 0
        same_srv_rate = 0
        dst_host_count = 0
        dst_host_srv_count = 0
        dst_host_same_srv_rate = 0
        dst_host_serror_rate = 0
        dst_host_srv_serror_rate = 0

        for pkt in packetList:
            if packet.src_ip == pkt.src_ip and pkt.dst_ip == packet.dst_ip:
                count += 1
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and packet.dst_port == pkt.dst_port:
                srv_count += 1
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and pkt.status_conn == "False":
                serror_rate += 1
            if packet.src_ip == pkt.src_ip and packet.dst_ip == pkt.dst_ip and packet.dst_port == pkt.dst_port \
                    and pkt.status_conn == "False":
                srv_serror_rate += 1
            if pkt.dst_ip == packet.dst_ip:
                dst_host_count += 1
            if pkt.dst_port == packet.dst_port:
                dst_host_srv_count += 1
            if pkt.dst_ip == packet.dst_ip and pkt.dst_port == packet.dst_port:
                dst_host_same_srv_rate += 1
            if pkt.dst_ip == packet.dst_ip and pkt.status_conn == "False":
                dst_host_serror_rate += 1
            if pkt.dst_port == packet.dst_port and pkt.status_conn == "False":
                dst_host_srv_serror_rate += 1
        if count != 0:
            serror_rate = serror_rate/count
            same_srv_rate = srv_count/count
        else:
            serror_rate
            same_srv_rate = 0
        if srv_count != 0:
            srv_serror_rate = srv_serror_rate/srv_count
        else:
            srv_serror_rate = 0
        if dst_host_count != 0:
            dst_host_same_srv_rate = dst_host_same_srv_rate/dst_host_count
            dst_host_serror_rate = dst_host_serror_rate/dst_host_count
        else:
            dst_host_same_srv_rate = 0
            dst_host_serror_rate = 0
        if dst_host_srv_count != 0:
            dst_host_srv_serror_rate = dst_host_srv_serror_rate/dst_host_srv_count
        else:
            dst_host_srv_serror_rate = 0

        return str(count) + "," + str(serror_rate) + "," + str(srv_serror_rate) \
               + "," + str(same_srv_rate) + "," + str(dst_host_count) + "," + str(dst_host_srv_count) \
               + "," + str(dst_host_same_srv_rate) + "," + str(dst_host_serror_rate) \
               + "," + str(dst_host_srv_serror_rate)

    def get_extract_path(self, src_path):
        fileExtract = ""
        if platform.system() == "Windows":
            list = src_path.split("\\")
            if list[-1].find(".pcap") != -1:
                fileExtract = os.getcwd() + "\\DatasetTest\\" + list[-1].replace(".pcap", ".csv")
            elif list[-1].find(".cap") != -1:
                fileExtract = os.getcwd() + "\\DatasetTest\\" + list[-1].replace(".cap", ".csv")
        elif platform.system() == "Linux":
            list = src_path.split("/")
            fileExtract = os.getcwd() + "/DatasetTest/" + list[-1].replace("pcap", "csv")
        else:
            print("Sorry, we do not support your system")
        return fileExtract

    def getFeature(self, src_path):
        FILEPATH = src_path
        print(FILEPATH)
        if os.path.getsize(FILEPATH) > 360:
            print("Start: " + FILEPATH)
            print(datetime.datetime.now())
            FILE_EXTRACT_PATH = self.get_extract_path(FILEPATH)
            pcap = pyshark.FileCapture(FILEPATH)
            featureTotal = ""
            featureTotalArray = []
            featureSet = set()
            featureSetFinal = set()
            packetList = []
            packetListStt = []

            index = 1
            for packet in pcap:
                print("Index packet %d" %index)
                index += 1
                protocol = self.get_protocol(packet)
                if protocol != "other":
                    src_ip = self.get_src_ip(packet)
                    dst_ip = self.get_dst_ip(packet)
                    src_port = self.get_src_port(packet, protocol)
                    dst_port = self.get_dst_port(packet, protocol)
                    service = self.get_service_http(protocol, dst_port)
                    flag = self.get_flag(packet, protocol)
                    sequence_number = self.get_seq_number(packet, protocol)
                    acknowledgment_number = self.get_ackn_number(packet, protocol)
                    packetList.append(Packet(src_ip, dst_ip, src_port, dst_port, protocol, service
                                             , flag, sequence_number, acknowledgment_number))
            pcap.close()

            ind = 1
            for packet in packetList:
                print("Index packetList %d" %ind)
                ind += 1
                status_conn = self.is_connection_success(ind, packet, packetList)
                packetListStt.append(PacketStt(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol,
                                            packet.service, packet.flag, packet.sequence_number, packet.acknowledgment_number, status_conn))

            i = 0
            for packet in packetListStt:
                print("Index packetListStt %d" %i)
                i += 1
                featureStrTuple = ""
                featureStr = ""

                featureStrTuple += packet.src_ip + ","
                featureStrTuple += packet.dst_ip + ","
                featureStrTuple += packet.src_port + ","
                featureStrTuple += packet.dst_port + ","
                featureStrTuple += packet.protocol + ","
                featureStrTuple += packet.service + ","
                # featureStrTuple += packet.flag + ","
                # featureStrTuple += packet.sequence_number + ","
                # featureStrTuple += packet.acknowledgment_number + ","
                featureStrTuple += packet.status_conn

                if featureStrTuple not in featureSet:
                    featureSet.add(featureStrTuple)
                else:
                    continue

                calcu_feature = self.get_calculate_feature(packet, packetListStt)

                featureStr += packet.src_ip + ","
                featureStr += packet.dst_ip + ","
                featureStr += packet.src_port + ","
                featureStr += packet.dst_port + ","
                featureStr += packet.protocol + ","
                featureStr += calcu_feature + ","
                if packet.service == "http":
                    service_http = 1
                else:
                    service_http = 0
                featureStr += str(service_http) + ","

                #flag_s0
                if packet.status_conn  == "False":
                    featureStr += "1" + ","
                else:
                    featureStr += "0" + ","
                #flag_sf
                if packet.status_conn == "True":
                    featureStr += "1" + ","
                else:
                    featureStr += "0"
                # featureStr += "\n"

                if featureStr not in featureSetFinal:
                    featureSetFinal.add(featureStr)
                else:
                    continue


                featureArray = featureStr.split(",")
                featureTotalArray.append(featureArray)
                featureTotal += featureStr

            if featureTotalArray != []:
                print("Done: " + FILEPATH)
                print(datetime.datetime.now())
            # if featureTotal != "":
            #     f = open(FILE_EXTRACT_PATH, "w+")
            #     f.write(featureTotal)
            #     f.close()
            #     print("Done: " + FILEPATH)
            #     print(datetime.datetime.now())

            predict.predict(featureTotalArray)
        else:
            if os.path.exists(FILEPATH):
                os.remove(FILEPATH)


def featureExtract():

    handlePcap = HandlePcap()
    LASTFILE = ""
    curDirWorking = ""
    if platform.system() == "Windows":
        curDirWorking = os.getcwd() + "\\PcapCapture\\*"
    elif platform.system() == "Linux":
        curDirWorking = os.getcwd() + "/PcapCapture/*"
    else:
        print("Sorry, we do not support your system")
    while True:
        # * means all if need specific format then *.pcap
        list_of_files = glob.glob(curDirWorking)
        if len(list_of_files) != 0:
            latest_file = max(list_of_files, key=os.path.getctime)
            if LASTFILE != latest_file:
                LASTFILE = latest_file
                # print(LASTFILE)
                # time.sleep(2)
                thread = Thread(target=handlePcap.getFeature(LASTFILE))
                thread.start()

        time.sleep(2)
