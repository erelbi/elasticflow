import socket
import logging
import binascii
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from netflow.v9 import V9ExportPacket
from datetime import datetime

es = Elasticsearch(["http://localhost:9200"])

# Protokol numaraları
IP_PROTOCOLS = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP", 5: "ST",
    6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON",
    11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET",
    16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP",
    21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2",
    25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4",
    30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC",
    35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
    40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag",
    45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP",
    51: "AH", 52: "I-NLSP", 53: "SwIPe", 54: "NARP", 55: "MOBILE",
    56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 89: "OSPF", 132: "SCTP"
}

# Yaygın port numaraları ve servisleri
COMMON_PORTS = {
    # Sistem Portları
    1: "tcpmux",
    7: "echo",
    9: "discard",
    13: "daytime",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    26: "rsftp",
    37: "time",
    49: "tacacs",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    70: "gopher",
    79: "finger",
    80: "http",
    88: "kerberos",
    109: "pop2",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    465: "smtps",
    514: "syslog",
    515: "printer",
    543: "klogin",
    544: "kshell",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql-server",
    1434: "ms-sql-monitor",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5901: "vnc-1",
    5902: "vnc-2",
    5903: "vnc-3",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    9300: "elasticsearch-nodes",
    27017: "mongodb",
    # Yaygın uygulama portları
    1194: "openvpn",
    1701: "l2tp",
    1812: "radius",
    1813: "radius-acct",
    3128: "squid-proxy",
    3690: "svn",
    5060: "sip",
    5061: "sips",
    6660: "irc-1",
    6661: "irc-2",
    6662: "irc-3",
    6663: "irc-4",
    6664: "irc-5",
    6665: "irc-6",
    6666: "irc-7",
    6667: "irc-8",
    6668: "irc-9",
    6669: "irc-10",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8081: "http-alt",
    8082: "http-alt",
    8083: "http-alt",
    8084: "http-alt",
    8085: "http-alt",
    8086: "http-alt",
    8087: "http-alt",
    8088: "http-alt",
    8089: "http-alt",
    8090: "http-alt",
    # Oyun Portları
    25565: "minecraft",
    27015: "source-game",
    27016: "source-game",
    27017: "source-game",
    27018: "source-game",
    27019: "source-game",
    # Güvenlik Duvarı/VPN
    500: "isakmp",
    4500: "ipsec-nat-t"
}

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

templates = {}

def get_service_name(port, protocol):
    """Port numarasına göre servis adını döndürür"""
    if not isinstance(port, int):
        return "unknown"
    
    service = COMMON_PORTS.get(port, "unknown")
    if service == "unknown" and port >= 49152:
        return "dynamic/private"
    elif service == "unknown" and port >= 1024:
        return "registered"
    return service

def create_index_if_not_exists(index_name):
    try:
        if not es.indices.exists(index=index_name):
            index_body = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"},
                        "protocol": {"type": "keyword"},
                        "in_bytes": {"type": "long"},
                        "out_bytes": {"type": "long"},
                        "src_port": {"type": "integer"},
                        "src_service": {"type": "keyword"},
                        "dst_port": {"type": "integer"},
                        "dst_service": {"type": "keyword"}
                    }
                }
            }
            es.indices.create(index=index_name, body=index_body)
            logger.info(f"{index_name} indeksi oluşturuldu.")
        else:
            logger.info(f"{index_name} indeksi zaten mevcut.")
    except Exception as e:
        logger.error(f"{index_name} indeks oluşturulurken hata: {e}")

def parse_netflow_v9_data(data):
    try:
        packet = V9ExportPacket(data, templates)

        for flow in packet.flows:
            src_ip = flow.data.get("IPV4_SRC_ADDR", flow.data.get("IPV6_SRC_ADDR", "N/A"))
            dst_ip = flow.data.get("IPV4_DST_ADDR", flow.data.get("IPV6_DST_ADDR", "N/A"))
            protocol_num = flow.data.get("PROTOCOL", "N/A")
            protocol = IP_PROTOCOLS.get(protocol_num, f"Unknown ({protocol_num})") if isinstance(protocol_num, int) else protocol_num
            in_bytes = flow.data.get("IN_BYTES", "N/A")
            out_bytes = flow.data.get("OUT_BYTES", "N/A")
            src_port = flow.data.get("L4_SRC_PORT", "N/A")
            dst_port = flow.data.get("L4_DST_PORT", "N/A")

            # Port numaralarının servis isimlerini al
            src_service = get_service_name(src_port, protocol) if isinstance(src_port, int) else "unknown"
            dst_service = get_service_name(dst_port, protocol) if isinstance(dst_port, int) else "unknown"
            
            doc = {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "in_bytes": in_bytes,
                "out_bytes": out_bytes,
                "src_port": src_port,
                "src_service": src_service,
                "dst_port": dst_port,
                "dst_service": dst_service
            }
            
            res = es.index(index="turksatflow", body=doc)
            logger.info(f"Veri Elasticsearch'e yazıldı: {res['result']}")
            
#            print(f"Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Protokol: {protocol}, "
#                  f"Gelen Bayt: {in_bytes}, Giden Bayt: {out_bytes}, "
#                  f"Kaynak Port: {src_port} ({src_service}), Hedef Port: {dst_port} ({dst_service})")
    except Exception as e:
        logger.error(f"Parse hatası: {e}")

def start_netflow_listener(host="0.0.0.0", port=2055):
    create_index_if_not_exists("turksatflow")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    logger.info(f"UDP {port} portu üzerinde dinleniyor.")

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            hex_data = binascii.hexlify(data).decode('utf-8')
            logger.info(f"Paket alındı - Boyut: {len(data)} bytes, Kaynak: {addr}")
            parse_netflow_v9_data(data)
    except KeyboardInterrupt:
        logger.info("Kapatılıyor...")
    finally:
        sock.close()

if __name__ == "__main__":
    start_netflow_listener()
