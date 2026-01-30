"""
Protocol analysis module for ProcShark.

Provides parsing and classification of network protocols including:
- HTTP request parsing
- DNS query parsing
- TLS/SSL detection
- QUIC detection
- Service identification by port
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set


# Well-known port to service mappings
PORT_SERVICES: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1883: "MQTT",
    1900: "SSDP",
    3306: "MYSQL",
    3389: "RDP",
    3478: "STUN",
    5060: "SIP",
    5061: "SIPS",
    5222: "XMPP",
    5432: "POSTGRES",
    5672: "AMQP",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8883: "MQTT-TLS",
    9200: "ELASTIC",
    27017: "MONGODB",
}

# HTTP methods for request detection
HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")

# TLS content types
TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17}  # ChangeCipherSpec, Alert, Handshake, Application
TLS_VERSIONS = {0x00, 0x01, 0x02, 0x03, 0x04}  # SSL 3.0, TLS 1.0-1.3

# DNS query types
DNS_QUERY_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    65: "HTTPS",
    99: "SPF",
    255: "ANY",
    256: "URI",
    257: "CAA",
}


@dataclass
class HTTPRequest:
    """Parsed HTTP request information."""
    method: str
    path: str
    host: Optional[str]

    def __str__(self) -> str:
        host_str = self.host or "-"
        return f"HTTP {self.method} host={host_str} path={self.path}"


@dataclass
class DNSQuery:
    """Parsed DNS query information."""
    qname: str
    qtype: Optional[int]
    qtype_name: Optional[str]

    def __str__(self) -> str:
        type_str = self.qtype_name or str(self.qtype) if self.qtype else ""
        if type_str:
            return f"DNS {self.qname} ({type_str})"
        return f"DNS {self.qname}"


@dataclass
class ProtocolInfo:
    """Protocol classification result."""
    protocol: str
    description: str
    is_encrypted: bool = False

    def __str__(self) -> str:
        return self.description


class ProtocolAnalyzer:
    """
    Analyzes network packets to identify protocols and extract metadata.

    Supports detection and parsing of:
    - HTTP requests (method, host, path)
    - DNS queries (domain name, query type)
    - TLS/SSL handshakes
    - QUIC protocol
    - Service identification by port
    """

    def __init__(self) -> None:
        """Initialize the protocol analyzer."""
        pass

    def identify_service(self, src_port: int, dst_port: int) -> str:
        """
        Identify the likely service based on port numbers.

        Args:
            src_port: Source port number
            dst_port: Destination port number

        Returns:
            Service name string (e.g., "HTTP", "DNS") or "unknown"
        """
        ports: Set[int] = {int(src_port or 0), int(dst_port or 0)}

        for port in ports:
            if port in PORT_SERVICES:
                return PORT_SERVICES[port]

        return "unknown"

    def parse_http(self, payload: bytes) -> Optional[HTTPRequest]:
        """
        Parse HTTP request from payload.

        Args:
            payload: Raw packet payload bytes

        Returns:
            HTTPRequest if valid HTTP request found, None otherwise
        """
        if not payload or len(payload) < 16:
            return None

        try:
            # Split header from body
            head = payload.split(b"\r\n\r\n", 1)[0]
            lines = head.split(b"\r\n")

            if not lines:
                return None

            # Parse request line
            first_line = lines[0].decode("ascii", errors="ignore")

            if not first_line.startswith(HTTP_METHODS):
                return None

            # Extract host header
            host: Optional[str] = None
            for line in lines[1:]:
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode("ascii", errors="ignore")
                    break

            # Parse method and path
            parts = first_line.split(" ")
            method = parts[0]
            path = parts[1] if len(parts) > 1 else "/"

            return HTTPRequest(method=method, path=path, host=host)

        except Exception:
            return None

    def parse_dns(self, payload: bytes) -> Optional[DNSQuery]:
        """
        Parse DNS query from payload.

        Args:
            payload: Raw packet payload bytes

        Returns:
            DNSQuery if valid DNS query found, None otherwise
        """
        if not payload or len(payload) < 12:
            return None

        try:
            # Check question count
            qdcount = int.from_bytes(payload[4:6], "big")
            if qdcount < 1:
                return None

            # Parse domain name labels
            i = 12
            labels: list[str] = []

            while i < len(payload):
                length = payload[i]

                if length == 0:
                    i += 1
                    break

                # Check for compression pointer
                if (length & 0xC0) == 0xC0:
                    return None

                i += 1
                if i + length > len(payload):
                    return None

                labels.append(payload[i:i + length].decode("ascii", errors="ignore"))
                i += length

            if not labels:
                return None

            qname = ".".join(labels)

            # Parse query type
            qtype: Optional[int] = None
            qtype_name: Optional[str] = None

            if i + 2 <= len(payload):
                qtype = int.from_bytes(payload[i:i + 2], "big")
                qtype_name = DNS_QUERY_TYPES.get(qtype)

            return DNSQuery(qname=qname, qtype=qtype, qtype_name=qtype_name)

        except Exception:
            return None

    def is_tls(self, payload: bytes) -> bool:
        """
        Check if payload appears to be TLS/SSL traffic.

        Args:
            payload: Raw packet payload bytes

        Returns:
            True if TLS handshake or record detected
        """
        if not payload or len(payload) < 5:
            return False

        content_type = payload[0]
        version_major = payload[1]
        version_minor = payload[2]

        return (
            content_type in TLS_CONTENT_TYPES and
            version_major == 0x03 and
            version_minor in TLS_VERSIONS
        )

    def is_quic(self, payload: bytes, src_port: int, dst_port: int, proto: str) -> bool:
        """
        Check if payload appears to be QUIC traffic.

        Args:
            payload: Raw packet payload bytes
            src_port: Source port number
            dst_port: Destination port number
            proto: Protocol string (must be "UDP")

        Returns:
            True if QUIC traffic detected
        """
        if proto != "UDP":
            return False

        if 443 not in (int(src_port or 0), int(dst_port or 0)):
            return False

        if not payload or len(payload) < 1:
            return False

        # QUIC long header has high bit set
        return (payload[0] & 0x80) != 0

    def classify(
        self,
        proto: str,
        src_port: int,
        dst_port: int,
        payload: bytes
    ) -> Optional[ProtocolInfo]:
        """
        Classify the application-layer protocol of a packet.

        Args:
            proto: Transport protocol ("TCP" or "UDP")
            src_port: Source port number
            dst_port: Destination port number
            payload: Raw packet payload bytes

        Returns:
            ProtocolInfo with classification result, or None if unclassified
        """
        if not payload:
            return None

        # Try HTTP parsing
        http = self.parse_http(payload)
        if http:
            return ProtocolInfo(
                protocol="HTTP",
                description=str(http),
                is_encrypted=False
            )

        # Try DNS parsing (on DNS ports)
        if 53 in (int(src_port or 0), int(dst_port or 0)):
            dns = self.parse_dns(payload)
            if dns:
                return ProtocolInfo(
                    protocol="DNS",
                    description=str(dns),
                    is_encrypted=False
                )

        # Check for TLS (on HTTPS port)
        if 443 in (int(src_port or 0), int(dst_port or 0)) and self.is_tls(payload):
            return ProtocolInfo(
                protocol="TLS",
                description="TLS handshake (HTTPS)",
                is_encrypted=True
            )

        # Check for QUIC
        if self.is_quic(payload, src_port, dst_port, proto):
            return ProtocolInfo(
                protocol="QUIC",
                description="QUIC (HTTP/3)",
                is_encrypted=True
            )

        return None

    def get_tcp_flags(self, syn: bool, ack: bool, fin: bool,
                      rst: bool, psh: bool, urg: bool) -> str:
        """
        Format TCP flags as a comma-separated string.

        Args:
            syn: SYN flag state
            ack: ACK flag state
            fin: FIN flag state
            rst: RST flag state
            psh: PSH flag state
            urg: URG flag state

        Returns:
            Comma-separated flag string (e.g., "SYN,ACK")
        """
        flags: list[str] = []

        if syn:
            flags.append("SYN")
        if ack:
            flags.append("ACK")
        if fin:
            flags.append("FIN")
        if rst:
            flags.append("RST")
        if psh:
            flags.append("PSH")
        if urg:
            flags.append("URG")

        return ",".join(flags)
