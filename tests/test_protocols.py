"""
Unit tests for ProcShark protocol analysis module.
"""

import pytest

from core.protocols import (
    ProtocolAnalyzer,
    HTTPRequest,
    DNSQuery,
    ProtocolInfo,
    PORT_SERVICES,
    DNS_QUERY_TYPES,
)


class TestProtocolAnalyzer:
    """Tests for ProtocolAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a ProtocolAnalyzer instance."""
        return ProtocolAnalyzer()

    # Service identification tests

    def test_identify_service_http(self, analyzer):
        """Test HTTP service identification."""
        assert analyzer.identify_service(12345, 80) == "HTTP"
        assert analyzer.identify_service(80, 12345) == "HTTP"

    def test_identify_service_https(self, analyzer):
        """Test HTTPS service identification."""
        assert analyzer.identify_service(12345, 443) == "HTTPS"
        assert analyzer.identify_service(443, 12345) == "HTTPS"

    def test_identify_service_dns(self, analyzer):
        """Test DNS service identification."""
        assert analyzer.identify_service(12345, 53) == "DNS"
        assert analyzer.identify_service(53, 12345) == "DNS"

    def test_identify_service_unknown(self, analyzer):
        """Test unknown service identification."""
        assert analyzer.identify_service(12345, 54321) == "unknown"

    def test_identify_service_multiple_known_ports(self, analyzer):
        """Test with multiple known ports (first match wins)."""
        # When both ports are known, any match should return a service
        result = analyzer.identify_service(22, 80)
        assert result in ("SSH", "HTTP")

    # HTTP parsing tests

    def test_parse_http_get_request(self, analyzer):
        """Test parsing a simple GET request."""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = analyzer.parse_http(payload)

        assert result is not None
        assert result.method == "GET"
        assert result.path == "/index.html"
        assert result.host == "example.com"

    def test_parse_http_post_request(self, analyzer):
        """Test parsing a POST request."""
        payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{}"
        result = analyzer.parse_http(payload)

        assert result is not None
        assert result.method == "POST"
        assert result.path == "/api/data"
        assert result.host == "api.example.com"

    def test_parse_http_no_host(self, analyzer):
        """Test parsing HTTP request without Host header."""
        payload = b"GET /path HTTP/1.1\r\n\r\n"
        result = analyzer.parse_http(payload)

        assert result is not None
        assert result.method == "GET"
        assert result.path == "/path"
        assert result.host is None

    def test_parse_http_invalid_payload(self, analyzer):
        """Test parsing invalid HTTP payload."""
        assert analyzer.parse_http(b"not http") is None
        assert analyzer.parse_http(b"") is None
        assert analyzer.parse_http(None) is None

    def test_parse_http_binary_data(self, analyzer):
        """Test parsing binary data (not HTTP)."""
        payload = bytes([0x16, 0x03, 0x01, 0x00, 0x05])  # TLS-like data
        assert analyzer.parse_http(payload) is None

    # DNS parsing tests

    def test_parse_dns_a_query(self, analyzer):
        """Test parsing a DNS A record query."""
        # DNS query for example.com (A record)
        payload = (
            b"\x00\x01"  # Transaction ID
            b"\x01\x00"  # Flags (standard query)
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs: 0
            b"\x00\x00"  # Authority RRs: 0
            b"\x00\x00"  # Additional RRs: 0
            b"\x07example\x03com\x00"  # Query name
            b"\x00\x01"  # Type: A
            b"\x00\x01"  # Class: IN
        )
        result = analyzer.parse_dns(payload)

        assert result is not None
        assert result.qname == "example.com"
        assert result.qtype == 1
        assert result.qtype_name == "A"

    def test_parse_dns_aaaa_query(self, analyzer):
        """Test parsing a DNS AAAA record query."""
        payload = (
            b"\x00\x02"  # Transaction ID
            b"\x01\x00"  # Flags
            b"\x00\x01"  # Questions: 1
            b"\x00\x00\x00\x00\x00\x00"  # RRs
            b"\x04test\x03org\x00"  # Query name: test.org
            b"\x00\x1c"  # Type: AAAA (28)
            b"\x00\x01"  # Class: IN
        )
        result = analyzer.parse_dns(payload)

        assert result is not None
        assert result.qname == "test.org"
        assert result.qtype == 28
        assert result.qtype_name == "AAAA"

    def test_parse_dns_invalid_payload(self, analyzer):
        """Test parsing invalid DNS payload."""
        assert analyzer.parse_dns(b"") is None
        assert analyzer.parse_dns(b"\x00" * 5) is None
        assert analyzer.parse_dns(None) is None

    def test_parse_dns_no_questions(self, analyzer):
        """Test parsing DNS with no questions."""
        payload = (
            b"\x00\x01"  # Transaction ID
            b"\x01\x00"  # Flags
            b"\x00\x00"  # Questions: 0
            b"\x00\x00\x00\x00\x00\x00"  # RRs
        )
        assert analyzer.parse_dns(payload) is None

    # TLS detection tests

    def test_is_tls_handshake(self, analyzer):
        """Test TLS handshake detection."""
        # TLS 1.2 ClientHello
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x05])
        assert analyzer.is_tls(payload) is True

    def test_is_tls_application_data(self, analyzer):
        """Test TLS application data detection."""
        # TLS application data
        payload = bytes([0x17, 0x03, 0x03, 0x00, 0x10])
        assert analyzer.is_tls(payload) is True

    def test_is_tls_ssl30(self, analyzer):
        """Test SSL 3.0 detection."""
        payload = bytes([0x16, 0x03, 0x00, 0x00, 0x05])
        assert analyzer.is_tls(payload) is True

    def test_is_tls_invalid(self, analyzer):
        """Test non-TLS data."""
        assert analyzer.is_tls(b"GET / HTTP") is False
        assert analyzer.is_tls(b"\x00\x00\x00\x00\x00") is False
        assert analyzer.is_tls(b"") is False

    # QUIC detection tests

    def test_is_quic_valid(self, analyzer):
        """Test QUIC detection on port 443."""
        # QUIC long header (high bit set)
        payload = bytes([0x80, 0x00, 0x00, 0x01])
        assert analyzer.is_quic(payload, 12345, 443, "UDP") is True

    def test_is_quic_wrong_port(self, analyzer):
        """Test QUIC detection on non-443 port."""
        payload = bytes([0x80, 0x00, 0x00, 0x01])
        assert analyzer.is_quic(payload, 12345, 8080, "UDP") is False

    def test_is_quic_wrong_protocol(self, analyzer):
        """Test QUIC detection with TCP."""
        payload = bytes([0x80, 0x00, 0x00, 0x01])
        assert analyzer.is_quic(payload, 12345, 443, "TCP") is False

    def test_is_quic_short_header(self, analyzer):
        """Test QUIC short header (not detected as QUIC)."""
        # Short header (high bit not set)
        payload = bytes([0x40, 0x00, 0x00, 0x01])
        assert analyzer.is_quic(payload, 12345, 443, "UDP") is False

    # Classification tests

    def test_classify_http(self, analyzer):
        """Test classification of HTTP traffic."""
        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        result = analyzer.classify("TCP", 12345, 80, payload)

        assert result is not None
        assert result.protocol == "HTTP"
        assert not result.is_encrypted

    def test_classify_dns(self, analyzer):
        """Test classification of DNS traffic."""
        payload = (
            b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06google\x03com\x00\x00\x01\x00\x01"
        )
        result = analyzer.classify("UDP", 12345, 53, payload)

        assert result is not None
        assert result.protocol == "DNS"
        assert "google.com" in result.description

    def test_classify_tls(self, analyzer):
        """Test classification of TLS traffic."""
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        result = analyzer.classify("TCP", 12345, 443, payload)

        assert result is not None
        assert result.protocol == "TLS"
        assert result.is_encrypted

    def test_classify_quic(self, analyzer):
        """Test classification of QUIC traffic."""
        payload = bytes([0xC0, 0x00, 0x00, 0x01, 0x00])
        result = analyzer.classify("UDP", 12345, 443, payload)

        assert result is not None
        assert result.protocol == "QUIC"
        assert result.is_encrypted

    def test_classify_empty_payload(self, analyzer):
        """Test classification with empty payload."""
        assert analyzer.classify("TCP", 12345, 80, b"") is None
        assert analyzer.classify("TCP", 12345, 80, None) is None

    # TCP flags tests

    def test_get_tcp_flags_syn(self, analyzer):
        """Test TCP SYN flag formatting."""
        result = analyzer.get_tcp_flags(syn=True, ack=False, fin=False,
                                        rst=False, psh=False, urg=False)
        assert result == "SYN"

    def test_get_tcp_flags_syn_ack(self, analyzer):
        """Test TCP SYN,ACK flag formatting."""
        result = analyzer.get_tcp_flags(syn=True, ack=True, fin=False,
                                        rst=False, psh=False, urg=False)
        assert result == "SYN,ACK"

    def test_get_tcp_flags_all(self, analyzer):
        """Test all TCP flags."""
        result = analyzer.get_tcp_flags(syn=True, ack=True, fin=True,
                                        rst=True, psh=True, urg=True)
        assert "SYN" in result
        assert "ACK" in result
        assert "FIN" in result
        assert "RST" in result
        assert "PSH" in result
        assert "URG" in result

    def test_get_tcp_flags_none(self, analyzer):
        """Test no TCP flags."""
        result = analyzer.get_tcp_flags(syn=False, ack=False, fin=False,
                                        rst=False, psh=False, urg=False)
        assert result == ""


class TestHTTPRequest:
    """Tests for HTTPRequest dataclass."""

    def test_str_with_host(self):
        """Test string representation with host."""
        req = HTTPRequest(method="GET", path="/api", host="example.com")
        assert str(req) == "HTTP GET host=example.com path=/api"

    def test_str_without_host(self):
        """Test string representation without host."""
        req = HTTPRequest(method="POST", path="/data", host=None)
        assert str(req) == "HTTP POST host=- path=/data"


class TestDNSQuery:
    """Tests for DNSQuery dataclass."""

    def test_str_with_type(self):
        """Test string representation with query type."""
        query = DNSQuery(qname="example.com", qtype=1, qtype_name="A")
        assert str(query) == "DNS example.com (A)"

    def test_str_without_type(self):
        """Test string representation without query type."""
        query = DNSQuery(qname="test.org", qtype=None, qtype_name=None)
        assert str(query) == "DNS test.org"


class TestProtocolInfo:
    """Tests for ProtocolInfo dataclass."""

    def test_str_representation(self):
        """Test string representation."""
        info = ProtocolInfo(protocol="HTTP", description="HTTP GET /path", is_encrypted=False)
        assert str(info) == "HTTP GET /path"

    def test_encrypted_flag(self):
        """Test encrypted flag."""
        tls = ProtocolInfo(protocol="TLS", description="TLS handshake", is_encrypted=True)
        assert tls.is_encrypted is True

        http = ProtocolInfo(protocol="HTTP", description="HTTP GET", is_encrypted=False)
        assert http.is_encrypted is False


class TestConstants:
    """Tests for module constants."""

    def test_port_services_common_ports(self):
        """Test common ports are defined."""
        assert PORT_SERVICES[80] == "HTTP"
        assert PORT_SERVICES[443] == "HTTPS"
        assert PORT_SERVICES[22] == "SSH"
        assert PORT_SERVICES[53] == "DNS"

    def test_dns_query_types_common_types(self):
        """Test common DNS query types are defined."""
        assert DNS_QUERY_TYPES[1] == "A"
        assert DNS_QUERY_TYPES[28] == "AAAA"
        assert DNS_QUERY_TYPES[5] == "CNAME"
        assert DNS_QUERY_TYPES[15] == "MX"
