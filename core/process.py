"""
Process correlation module for ProcShark.

Maps network connections to their owning processes using psutil,
enabling per-process traffic analysis and filtering.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple

import psutil


@dataclass
class ProcessInfo:
    """Information about a process."""
    pid: int
    name: str
    exe: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.name}({self.pid})"


@dataclass
class ConnectionKey:
    """Unique identifier for a network connection."""
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    def __hash__(self) -> int:
        return hash((self.proto, self.local_ip, self.local_port,
                    self.remote_ip, self.remote_port))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConnectionKey):
            return False
        return (
            self.proto == other.proto and
            self.local_ip == other.local_ip and
            self.local_port == other.local_port and
            self.remote_ip == other.remote_ip and
            self.remote_port == other.remote_port
        )


@dataclass
class ProcessFilter:
    """Filter configuration for process-based filtering."""
    target_path: str
    is_directory: bool
    normalized_path: str = field(init=False)

    def __post_init__(self) -> None:
        self.normalized_path = normalize_path(self.target_path)

    def matches(self, exe_path: Optional[str]) -> bool:
        """
        Check if an executable path matches this filter.

        Args:
            exe_path: Path to the executable to check

        Returns:
            True if the path matches the filter
        """
        if not exe_path:
            return False

        normalized_exe = normalize_path(exe_path)

        if self.is_directory:
            dir_path = self.normalized_path
            if not dir_path.endswith(os.sep):
                dir_path = dir_path + os.sep
            return normalized_exe.startswith(dir_path)
        else:
            return normalized_exe == self.normalized_path


def normalize_path(path: str) -> str:
    """
    Normalize a file path for comparison.

    Args:
        path: File path to normalize

    Returns:
        Normalized lowercase path
    """
    try:
        path = os.path.expandvars(os.path.expanduser(path))
        path = os.path.abspath(path)
        path = os.path.normpath(path)
        return path.lower()
    except Exception:
        return (path or "").lower()


def normalize_ip(ip: Optional[str]) -> str:
    """
    Normalize an IP address string.

    Args:
        ip: IP address or None

    Returns:
        IP address string or empty string if None
    """
    return str(ip) if ip is not None else ""


def is_loopback(ip: str) -> bool:
    """
    Check if an IP address is a loopback address.

    Args:
        ip: IP address string

    Returns:
        True if loopback (127.0.0.1 or ::1)
    """
    return ip == "127.0.0.1" or ip == "::1"


class ProcessCorrelator:
    """
    Correlates network connections with their owning processes.

    Uses psutil to maintain a mapping of connection tuples to process
    information, enabling real-time process identification for captured
    network traffic.
    """

    def __init__(self, process_filter: Optional[ProcessFilter] = None) -> None:
        """
        Initialize the process correlator.

        Args:
            process_filter: Optional filter to limit to specific processes
        """
        self._connection_map: dict[ConnectionKey, ProcessInfo] = {}
        self._name_cache: dict[int, Optional[str]] = {}
        self._process_filter = process_filter
        self._allowed_pids: Optional[Set[int]] = None

    def _get_process_name(self, pid: int) -> Optional[str]:
        """
        Get the name of a process by PID, with caching.

        Args:
            pid: Process ID

        Returns:
            Process name or None if not found
        """
        if not pid:
            return None

        if pid in self._name_cache:
            return self._name_cache[pid]

        try:
            self._name_cache[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self._name_cache[pid] = None

        return self._name_cache[pid]

    def refresh(self) -> None:
        """
        Refresh the connection-to-process mapping.

        Queries psutil for all active network connections and builds
        a lookup table for fast process identification.
        """
        self._connection_map.clear()
        self._name_cache.clear()

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            connections = []

        for conn in connections:
            try:
                if not conn.laddr:
                    continue

                # Determine protocol
                if conn.type == socket.SOCK_STREAM:
                    proto = "TCP"
                elif conn.type == socket.SOCK_DGRAM:
                    proto = "UDP"
                else:
                    continue

                local_ip = normalize_ip(conn.laddr.ip)
                local_port = conn.laddr.port

                remote_ip = ""
                remote_port = 0
                if conn.raddr:
                    remote_ip = normalize_ip(conn.raddr.ip)
                    remote_port = conn.raddr.port

                pid = conn.pid
                name = self._get_process_name(pid) if pid else None

                if not pid or not name:
                    continue

                process_info = ProcessInfo(pid=pid, name=name)

                # Store both directions for lookup
                key1 = ConnectionKey(proto, local_ip, local_port, remote_ip, remote_port)
                key2 = ConnectionKey(proto, remote_ip, remote_port, local_ip, local_port)

                self._connection_map[key1] = process_info
                self._connection_map[key2] = process_info

                # For UDP, also store wildcard remote endpoint
                if proto == "UDP" and remote_ip == "" and remote_port == 0:
                    key3 = ConnectionKey("UDP", local_ip, local_port, "", 0)
                    self._connection_map[key3] = process_info

            except Exception:
                continue

    def refresh_allowed_pids(self) -> None:
        """
        Refresh the set of allowed PIDs based on the process filter.

        Only relevant when a process filter is configured.
        """
        if not self._process_filter:
            self._allowed_pids = None
            return

        allowed: Set[int] = set()

        for proc in psutil.process_iter(attrs=["pid", "exe"]):
            try:
                pid = proc.info.get("pid")
                exe = proc.info.get("exe")

                if pid and exe and self._process_filter.matches(exe):
                    allowed.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._allowed_pids = allowed

    def lookup(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int
    ) -> Optional[ProcessInfo]:
        """
        Look up the process associated with a connection.

        Args:
            proto: Protocol ("TCP" or "UDP")
            src_ip: Source IP address
            src_port: Source port number
            dst_ip: Destination IP address
            dst_port: Destination port number

        Returns:
            ProcessInfo if found, None otherwise
        """
        # Try exact match
        key = ConnectionKey(proto, src_ip, src_port, dst_ip, dst_port)
        if key in self._connection_map:
            return self._connection_map[key]

        # Try reverse direction
        key = ConnectionKey(proto, dst_ip, dst_port, src_ip, src_port)
        if key in self._connection_map:
            return self._connection_map[key]

        # For UDP, try wildcard lookups
        if proto == "UDP":
            key = ConnectionKey("UDP", src_ip, src_port, "", 0)
            if key in self._connection_map:
                return self._connection_map[key]

            key = ConnectionKey("UDP", dst_ip, dst_port, "", 0)
            if key in self._connection_map:
                return self._connection_map[key]

        return None

    def is_pid_allowed(self, pid: Optional[int]) -> bool:
        """
        Check if a PID is allowed by the current filter.

        Args:
            pid: Process ID to check

        Returns:
            True if allowed (or no filter active), False otherwise
        """
        if self._allowed_pids is None:
            return True

        if pid is None:
            return False

        return pid in self._allowed_pids

    @property
    def filter_active(self) -> bool:
        """Check if process filtering is active."""
        return self._process_filter is not None

    @property
    def allowed_pids(self) -> Optional[Set[int]]:
        """Get the set of currently allowed PIDs."""
        return self._allowed_pids
