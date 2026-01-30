"""
Statistics module for ProcShark.

Tracks and computes live statistics about captured network traffic
including packet counts, bandwidth, and per-process breakdowns.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from core.capture import PacketInfo
    from core.process import ProcessInfo


def format_bytes(num_bytes: float) -> str:
    """
    Format byte count as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_rate(bytes_per_second: float) -> str:
    """
    Format bandwidth rate as human-readable string.

    Args:
        bytes_per_second: Bytes per second

    Returns:
        Formatted string (e.g., "1.5 MB/s")
    """
    return format_bytes(bytes_per_second) + "/s"


@dataclass
class TimeWindow:
    """Sliding time window for rate calculations."""
    duration: float = 1.0  # Window duration in seconds
    _samples: List[Tuple[float, int]] = field(default_factory=list)

    def add_sample(self, timestamp: float, value: int) -> None:
        """Add a sample to the window."""
        self._samples.append((timestamp, value))
        self._prune(timestamp)

    def _prune(self, current_time: float) -> None:
        """Remove samples outside the window."""
        cutoff = current_time - self.duration
        self._samples = [
            (ts, val) for ts, val in self._samples
            if ts >= cutoff
        ]

    def sum(self, current_time: Optional[float] = None) -> int:
        """Get sum of values in window."""
        if current_time:
            self._prune(current_time)
        return sum(val for _, val in self._samples)

    def rate(self, current_time: Optional[float] = None) -> float:
        """Get rate (sum / duration) for the window."""
        total = self.sum(current_time)
        return total / self.duration if self.duration > 0 else 0


class Statistics:
    """
    Live statistics tracker for network capture.

    Tracks:
    - Total packet count and byte count
    - Per-second packet and bandwidth rates
    - Protocol distribution
    - Per-process traffic breakdown
    - Service distribution
    - Direction breakdown (inbound/outbound)
    """

    def __init__(self, window_duration: float = 1.0) -> None:
        """
        Initialize statistics tracker.

        Args:
            window_duration: Duration of sliding window for rate calculations
        """
        self._start_time = time.time()
        self._window_duration = window_duration

        # Totals
        self._total_packets = 0
        self._total_bytes = 0

        # Rate windows
        self._packet_window = TimeWindow(duration=window_duration)
        self._byte_window = TimeWindow(duration=window_duration)

        # Breakdowns
        self._protocol_counts: Dict[str, int] = defaultdict(int)
        self._protocol_bytes: Dict[str, int] = defaultdict(int)

        self._process_counts: Dict[str, int] = defaultdict(int)
        self._process_bytes: Dict[str, int] = defaultdict(int)

        self._service_counts: Dict[str, int] = defaultdict(int)
        self._direction_counts: Dict[str, int] = defaultdict(int)
        self._direction_bytes: Dict[str, int] = defaultdict(int)

        # Connection tracking
        self._unique_connections: set = set()
        self._unique_ips: set = set()

    def record_packet(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"] = None,
        service: Optional[str] = None
    ) -> None:
        """
        Record a captured packet.

        Args:
            packet: Captured packet info
            process: Associated process info
            service: Identified service name
        """
        current_time = time.time()
        size = packet.size

        # Update totals
        self._total_packets += 1
        self._total_bytes += size

        # Update rate windows
        self._packet_window.add_sample(current_time, 1)
        self._byte_window.add_sample(current_time, size)

        # Update protocol breakdown
        self._protocol_counts[packet.protocol] += 1
        self._protocol_bytes[packet.protocol] += size

        # Update process breakdown
        if process:
            proc_key = str(process)
            self._process_counts[proc_key] += 1
            self._process_bytes[proc_key] += size

        # Update service breakdown
        if service and service != "unknown":
            self._service_counts[service] += 1

        # Update direction breakdown
        self._direction_counts[packet.direction] += 1
        self._direction_bytes[packet.direction] += size

        # Track unique connections and IPs
        conn_key = (
            packet.protocol,
            min(packet.src_ip, packet.dst_ip),
            min(packet.src_port, packet.dst_port),
            max(packet.src_ip, packet.dst_ip),
            max(packet.src_port, packet.dst_port),
        )
        self._unique_connections.add(conn_key)
        self._unique_ips.add(packet.src_ip)
        self._unique_ips.add(packet.dst_ip)

    @property
    def total_packets(self) -> int:
        """Get total packet count."""
        return self._total_packets

    @property
    def total_bytes(self) -> int:
        """Get total byte count."""
        return self._total_bytes

    @property
    def total_bytes_str(self) -> str:
        """Get formatted total bytes."""
        return format_bytes(self._total_bytes)

    @property
    def packets_per_second(self) -> float:
        """Get current packets per second rate."""
        return self._packet_window.rate(time.time())

    @property
    def bytes_per_second(self) -> float:
        """Get current bytes per second rate."""
        return self._byte_window.rate(time.time())

    @property
    def bandwidth_str(self) -> str:
        """Get formatted current bandwidth."""
        return format_rate(self.bytes_per_second)

    @property
    def protocol_counts(self) -> Dict[str, int]:
        """Get packet counts by protocol."""
        return dict(self._protocol_counts)

    @property
    def protocol_bytes(self) -> Dict[str, int]:
        """Get byte counts by protocol."""
        return dict(self._protocol_bytes)

    @property
    def service_counts(self) -> Dict[str, int]:
        """Get packet counts by service."""
        return dict(self._service_counts)

    @property
    def direction_counts(self) -> Dict[str, int]:
        """Get packet counts by direction."""
        return dict(self._direction_counts)

    @property
    def direction_bytes(self) -> Dict[str, int]:
        """Get byte counts by direction."""
        return dict(self._direction_bytes)

    @property
    def unique_connections(self) -> int:
        """Get number of unique connections seen."""
        return len(self._unique_connections)

    @property
    def unique_ips(self) -> int:
        """Get number of unique IP addresses seen."""
        return len(self._unique_ips)

    @property
    def top_processes(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top processes by packet count.

        Args:
            limit: Maximum number of processes to return

        Returns:
            List of (process_name, packet_count) tuples
        """
        sorted_procs = sorted(
            self._process_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_procs[:limit]

    @property
    def top_processes_by_bytes(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top processes by byte count.

        Args:
            limit: Maximum number of processes to return

        Returns:
            List of (process_name, byte_count) tuples
        """
        sorted_procs = sorted(
            self._process_bytes.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_procs[:limit]

    @property
    def top_services(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top services by packet count.

        Args:
            limit: Maximum number of services to return

        Returns:
            List of (service_name, packet_count) tuples
        """
        sorted_services = sorted(
            self._service_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_services[:limit]

    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time since tracking started."""
        return time.time() - self._start_time

    @property
    def average_packet_size(self) -> float:
        """Get average packet size in bytes."""
        if self._total_packets == 0:
            return 0
        return self._total_bytes / self._total_packets

    def summary(self) -> Dict:
        """
        Get complete statistics summary.

        Returns:
            Dictionary with all statistics
        """
        return {
            "elapsed_seconds": self.elapsed_seconds,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_bytes_formatted": self.total_bytes_str,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "bandwidth_formatted": self.bandwidth_str,
            "average_packet_size": self.average_packet_size,
            "unique_connections": self.unique_connections,
            "unique_ips": self.unique_ips,
            "protocol_counts": self.protocol_counts,
            "protocol_bytes": self.protocol_bytes,
            "service_counts": self.service_counts,
            "direction_counts": self.direction_counts,
            "direction_bytes": self.direction_bytes,
            "top_processes": self.top_processes,
        }

    def reset(self) -> None:
        """Reset all statistics."""
        self._start_time = time.time()
        self._total_packets = 0
        self._total_bytes = 0
        self._packet_window = TimeWindow(duration=self._window_duration)
        self._byte_window = TimeWindow(duration=self._window_duration)
        self._protocol_counts.clear()
        self._protocol_bytes.clear()
        self._process_counts.clear()
        self._process_bytes.clear()
        self._service_counts.clear()
        self._direction_counts.clear()
        self._direction_bytes.clear()
        self._unique_connections.clear()
        self._unique_ips.clear()
