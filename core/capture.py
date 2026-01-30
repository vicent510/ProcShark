"""
Packet capture module for ProcShark.

Provides packet capture functionality using pydivert (WinDivert wrapper)
for Windows network traffic interception.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    import pydivert


@dataclass
class PacketInfo:
    """Captured packet information."""
    timestamp: datetime
    direction: str  # "IN" or "OUT"
    protocol: str  # "TCP", "UDP", or "IP"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    size: int
    payload: bytes
    tcp_flags: str
    raw_packet: Optional[bytes] = None

    @property
    def source(self) -> str:
        """Format source as ip:port string."""
        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination(self) -> str:
        """Format destination as ip:port string."""
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def timestamp_str(self) -> str:
        """Format timestamp as HH:MM:SS.mmm string."""
        return self.timestamp.strftime("%H:%M:%S.%f")[:-3]

    def payload_hex(self, max_bytes: int = 1024) -> str:
        """
        Get payload as hexadecimal string.

        Args:
            max_bytes: Maximum bytes to include

        Returns:
            Hexadecimal string representation
        """
        data = self.payload[:max_bytes] if max_bytes > 0 else self.payload
        return binascii.hexlify(data).decode("ascii")

    def payload_ascii(self, max_bytes: int = 1024) -> str:
        """
        Get payload as printable ASCII string.

        Non-printable characters are replaced with dots.

        Args:
            max_bytes: Maximum bytes to include

        Returns:
            ASCII representation with non-printable chars as dots
        """
        data = self.payload[:max_bytes] if max_bytes > 0 else self.payload

        # Decode as Latin-1 (1:1 byte mapping) and replace control chars
        text = data.decode("latin-1", errors="strict")
        return "".join(
            ch if (32 <= ord(ch) < 127 or 159 < ord(ch) < 256) else "."
            for ch in text
        )


def _get_tcp_flags(tcp_header: "pydivert.TCPHeader") -> str:
    """
    Extract TCP flags from a packet.

    Args:
        tcp_header: pydivert TCP header object

    Returns:
        Comma-separated flag string
    """
    flags: list[str] = []

    if tcp_header.syn:
        flags.append("SYN")
    if tcp_header.ack:
        flags.append("ACK")
    if tcp_header.fin:
        flags.append("FIN")
    if tcp_header.rst:
        flags.append("RST")
    if tcp_header.psh:
        flags.append("PSH")
    if tcp_header.urg:
        flags.append("URG")

    return ",".join(flags)


class PacketCapture:
    """
    Network packet capture using WinDivert.

    Captures IPv4 and IPv6 TCP/UDP traffic, providing packet-level
    information including payload data.

    Note: Requires Administrator privileges on Windows.
    """

    # Default capture filter: IPv4/IPv6 TCP/UDP traffic
    DEFAULT_FILTER = "(ip or ipv6) and (tcp or udp)"

    def __init__(
        self,
        filter_string: Optional[str] = None,
        include_loopback: bool = True
    ) -> None:
        """
        Initialize the packet capture.

        Args:
            filter_string: WinDivert filter string (default captures TCP/UDP)
            include_loopback: Whether to include loopback traffic
        """
        self._filter = filter_string or self.DEFAULT_FILTER
        self._include_loopback = include_loopback
        self._handle: Optional["pydivert.WinDivert"] = None
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if capture is currently active."""
        return self._running

    def start(self) -> None:
        """
        Start packet capture.

        Raises:
            PermissionError: If not running as Administrator
            RuntimeError: If capture is already running
        """
        if self._running:
            raise RuntimeError("Capture is already running")

        import pydivert

        try:
            self._handle = pydivert.WinDivert(self._filter)
            self._handle.open()
            self._running = True
        except Exception as e:
            if "access" in str(e).lower():
                raise PermissionError(
                    "Administrator privileges required for packet capture"
                ) from e
            raise

    def stop(self) -> None:
        """Stop packet capture and release resources."""
        self._running = False

        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass
            self._handle = None

    def __enter__(self) -> "PacketCapture":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.stop()

    def capture(self) -> Iterator[PacketInfo]:
        """
        Generator that yields captured packets.

        Yields:
            PacketInfo for each captured packet

        Note:
            Packets are forwarded (re-injected) after capture.
            This is a blocking generator that runs until stop() is called.
        """
        if not self._running or not self._handle:
            raise RuntimeError("Capture not started")

        while self._running:
            try:
                packet = self._handle.recv()

                # Extract basic info
                direction = "OUT" if packet.is_outbound else "IN"

                if packet.tcp:
                    protocol = "TCP"
                elif packet.udp:
                    protocol = "UDP"
                else:
                    protocol = "IP"

                src_ip = str(packet.src_addr) if packet.src_addr else ""
                dst_ip = str(packet.dst_addr) if packet.dst_addr else ""
                src_port = int(packet.src_port or 0)
                dst_port = int(packet.dst_port or 0)

                # Filter loopback if requested
                if not self._include_loopback:
                    if src_ip in ("127.0.0.1", "::1") or dst_ip in ("127.0.0.1", "::1"):
                        self._handle.send(packet)
                        continue

                # Get TCP flags
                tcp_flags = ""
                if packet.tcp:
                    tcp_flags = _get_tcp_flags(packet.tcp)

                # Create packet info
                info = PacketInfo(
                    timestamp=datetime.now(),
                    direction=direction,
                    protocol=protocol,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    size=len(packet.raw) if packet.raw else 0,
                    payload=packet.payload or b"",
                    tcp_flags=tcp_flags,
                    raw_packet=packet.raw
                )

                # Forward the packet
                self._handle.send(packet)

                yield info

            except Exception as e:
                if not self._running:
                    break
                # Log error but continue capturing
                continue

    def capture_one(self) -> Optional[PacketInfo]:
        """
        Capture a single packet.

        Returns:
            PacketInfo for the captured packet, or None on error
        """
        for packet in self.capture():
            return packet
        return None
