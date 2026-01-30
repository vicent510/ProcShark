"""
Export module for ProcShark.

Provides functionality to export captured packets to JSON and CSV formats
for offline analysis and reporting.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from enum import Enum
from typing import Optional, TextIO, TYPE_CHECKING

if TYPE_CHECKING:
    from core.capture import PacketInfo
    from core.process import ProcessInfo
    from core.protocols import ProtocolInfo


class ExportFormat(Enum):
    """Supported export formats."""
    JSON = "json"
    CSV = "csv"


def detect_format(filename: str) -> ExportFormat:
    """
    Detect export format from filename extension.

    Args:
        filename: Output filename

    Returns:
        Detected ExportFormat

    Raises:
        ValueError: If format cannot be determined
    """
    ext = os.path.splitext(filename)[1].lower()

    if ext == ".json":
        return ExportFormat.JSON
    elif ext == ".csv":
        return ExportFormat.CSV
    else:
        raise ValueError(
            f"Cannot determine export format from extension '{ext}'. "
            "Use --export-format to specify json or csv."
        )


class Exporter:
    """
    Exports captured packets to file.

    Supports JSON and CSV output formats with automatic format detection
    based on file extension.
    """

    # CSV column headers
    CSV_HEADERS = [
        "timestamp",
        "direction",
        "protocol",
        "tcp_flags",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "size",
        "service",
        "process_name",
        "process_pid",
        "app_protocol",
        "app_description",
        "payload_hex",
    ]

    def __init__(
        self,
        filename: str,
        format: Optional[ExportFormat] = None,
        include_payload: bool = True,
        max_payload: int = 1024
    ) -> None:
        """
        Initialize the exporter.

        Args:
            filename: Output file path
            format: Export format (auto-detected if None)
            include_payload: Whether to include payload in export
            max_payload: Maximum payload bytes to export
        """
        self._filename = filename
        self._format = format or detect_format(filename)
        self._include_payload = include_payload
        self._max_payload = max_payload

        self._file: Optional[TextIO] = None
        self._csv_writer: Optional[csv.DictWriter] = None
        self._json_packets: list[dict] = []
        self._packet_count = 0

        self._open_file()

    def _open_file(self) -> None:
        """Open the output file and initialize writer."""
        self._file = open(self._filename, "w", newline="", encoding="utf-8")

        if self._format == ExportFormat.CSV:
            self._csv_writer = csv.DictWriter(
                self._file,
                fieldnames=self.CSV_HEADERS,
                extrasaction="ignore"
            )
            self._csv_writer.writeheader()

    def _packet_to_dict(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> dict:
        """
        Convert packet to dictionary for export.

        Args:
            packet: Captured packet
            process: Associated process info
            service: Identified service name
            app_info: Application layer protocol info

        Returns:
            Dictionary representation of the packet
        """
        data = {
            "timestamp": packet.timestamp.isoformat(),
            "direction": packet.direction,
            "protocol": packet.protocol,
            "tcp_flags": packet.tcp_flags,
            "src_ip": packet.src_ip,
            "src_port": packet.src_port,
            "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port,
            "size": packet.size,
            "service": service,
            "process_name": process.name if process else None,
            "process_pid": process.pid if process else None,
            "app_protocol": app_info.protocol if app_info else None,
            "app_description": app_info.description if app_info else None,
        }

        if self._include_payload and packet.payload:
            data["payload_hex"] = packet.payload_hex(self._max_payload)

        return data

    def write_packet(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> None:
        """
        Write a packet to the export file.

        Args:
            packet: Captured packet
            process: Associated process info
            service: Identified service name
            app_info: Application layer protocol info
        """
        data = self._packet_to_dict(packet, process, service, app_info)
        self._packet_count += 1

        if self._format == ExportFormat.CSV:
            self._write_csv(data)
        else:
            self._json_packets.append(data)

    def _write_csv(self, data: dict) -> None:
        """Write a single row to CSV."""
        if self._csv_writer and self._file:
            self._csv_writer.writerow(data)
            self._file.flush()

    def close(self) -> None:
        """Close the export file and finalize output."""
        if self._format == ExportFormat.JSON and self._file:
            # Write all JSON data at once
            export_data = {
                "export_info": {
                    "tool": "ProcShark",
                    "version": "1.0.0",
                    "export_time": datetime.now().isoformat(),
                    "packet_count": self._packet_count,
                },
                "packets": self._json_packets,
            }
            json.dump(export_data, self._file, indent=2)

        if self._file:
            self._file.close()
            self._file = None

    @property
    def packet_count(self) -> int:
        """Get the number of packets exported."""
        return self._packet_count

    @property
    def filename(self) -> str:
        """Get the export filename."""
        return self._filename

    def __enter__(self) -> "Exporter":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


class StreamingJSONExporter(Exporter):
    """
    Streaming JSON exporter for large captures.

    Writes packets incrementally in JSON Lines format (one JSON object per line)
    to avoid memory issues with very large captures.
    """

    def __init__(
        self,
        filename: str,
        include_payload: bool = True,
        max_payload: int = 1024
    ) -> None:
        """
        Initialize the streaming exporter.

        Args:
            filename: Output file path
            include_payload: Whether to include payload
            max_payload: Maximum payload bytes
        """
        self._filename = filename
        self._include_payload = include_payload
        self._max_payload = max_payload
        self._format = ExportFormat.JSON
        self._file: Optional[TextIO] = None
        self._packet_count = 0
        self._csv_writer = None
        self._json_packets = []

        self._file = open(self._filename, "w", encoding="utf-8")

    def write_packet(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> None:
        """Write packet as a single JSON line."""
        data = self._packet_to_dict(packet, process, service, app_info)
        self._packet_count += 1

        if self._file:
            self._file.write(json.dumps(data))
            self._file.write("\n")
            self._file.flush()

    def close(self) -> None:
        """Close the export file."""
        if self._file:
            self._file.close()
            self._file = None
