"""
Command-line interface for ProcShark.

Parses command-line arguments and orchestrates the capture,
display, and export functionality.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional, Set

from core import __version__
from core.capture import PacketCapture, PacketInfo
from core.process import ProcessCorrelator, ProcessFilter, ProcessInfo, is_loopback
from core.protocols import ProtocolAnalyzer
from core.display import Display
from core.export import Exporter, ExportFormat
from core.stats import Statistics


# Supported protocol filters
SUPPORTED_PROTOCOLS = {"tcp", "udp", "http", "https", "dns", "tls", "quic", "all"}


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="procshark",
        description="Network traffic analyzer with process correlation. "
                    "Captures network packets and identifies the processes responsible.",
        epilog="Requires Administrator privileges on Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Capture options
    capture_group = parser.add_argument_group("Capture Options")
    capture_group.add_argument(
        "-f", "--filter",
        dest="filter_path",
        metavar="PATH",
        help="Filter by executable path or directory"
    )
    capture_group.add_argument(
        "-p", "--protocol",
        dest="protocols",
        metavar="PROTO",
        help="Filter by protocol (comma-separated: tcp,udp,http,dns,tls,quic,all)"
    )
    capture_group.add_argument(
        "--exclude-protocol",
        dest="exclude_protocols",
        metavar="PROTO",
        help="Exclude protocols (comma-separated)"
    )
    capture_group.add_argument(
        "--no-loopback",
        action="store_true",
        help="Hide loopback traffic (127.0.0.1, ::1)"
    )

    # Display options
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument(
        "--no-payload",
        action="store_true",
        help="Don't show packet payload"
    )
    display_group.add_argument(
        "--max-payload",
        type=int,
        default=1024,
        metavar="N",
        help="Maximum payload bytes to display (default: 1024)"
    )
    display_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    display_group.add_argument(
        "--compact",
        action="store_true",
        help="Use compact single-line output format"
    )

    # Export options
    export_group = parser.add_argument_group("Export Options")
    export_group.add_argument(
        "--export",
        dest="export_file",
        metavar="FILE",
        help="Export captured packets to file (JSON or CSV)"
    )
    export_group.add_argument(
        "--export-format",
        choices=["json", "csv"],
        metavar="FMT",
        help="Force export format (auto-detected from extension by default)"
    )

    # Statistics options
    stats_group = parser.add_argument_group("Statistics Options")
    stats_group.add_argument(
        "--stats",
        action="store_true",
        help="Show live statistics panel"
    )
    stats_group.add_argument(
        "--stats-interval",
        type=float,
        default=1.0,
        metavar="N",
        help="Statistics refresh interval in seconds (default: 1.0)"
    )

    # Other options
    other_group = parser.add_argument_group("Other Options")
    other_group.add_argument(
        "--refresh",
        type=float,
        default=0.5,
        metavar="N",
        help="PID map refresh interval in seconds (default: 0.5)"
    )
    other_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    other_group.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser


def parse_protocols(protocol_str: Optional[str]) -> Optional[Set[str]]:
    """
    Parse protocol filter string.

    Args:
        protocol_str: Comma-separated protocol list

    Returns:
        Set of lowercase protocol names, or None if no filter
    """
    if not protocol_str:
        return None

    protocols = {p.strip().lower() for p in protocol_str.split(",")}

    # Validate protocols
    invalid = protocols - SUPPORTED_PROTOCOLS
    if invalid:
        raise ValueError(f"Unknown protocol(s): {', '.join(invalid)}")

    if "all" in protocols:
        return None

    return protocols


def should_include_packet(
    packet: PacketInfo,
    app_protocol: Optional[str],
    include_protocols: Optional[Set[str]],
    exclude_protocols: Optional[Set[str]]
) -> bool:
    """
    Check if a packet should be included based on protocol filters.

    Args:
        packet: Captured packet
        app_protocol: Detected application protocol (HTTP, DNS, etc.)
        include_protocols: Protocols to include (None = all)
        exclude_protocols: Protocols to exclude (None = none)

    Returns:
        True if packet should be included
    """
    transport = packet.protocol.lower()
    app = app_protocol.lower() if app_protocol else None

    # Check exclusions first
    if exclude_protocols:
        if transport in exclude_protocols:
            return False
        if app and app in exclude_protocols:
            return False

    # Check inclusions
    if include_protocols:
        if transport in include_protocols:
            return True
        if app and app in include_protocols:
            return True
        # Special cases
        if "https" in include_protocols and app == "tls":
            return True
        if "http" in include_protocols and app == "http":
            return True
        return False

    return True


def main() -> int:
    """
    Main entry point for ProcShark CLI.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    args = parser.parse_args()

    # Initialize display
    display = Display(
        show_payload=not args.no_payload,
        max_payload=args.max_payload,
        use_color=not args.no_color,
        compact=args.compact
    )

    # Parse protocol filters
    try:
        include_protocols = parse_protocols(args.protocols)
        exclude_protocols = parse_protocols(args.exclude_protocols)
    except ValueError as e:
        display.print_error(str(e))
        return 1

    # Initialize process filter
    process_filter: Optional[ProcessFilter] = None
    if args.filter_path:
        try:
            is_dir = os.path.isdir(args.filter_path)
        except Exception:
            is_dir = args.filter_path.endswith(os.sep) or args.filter_path.endswith("/")

        process_filter = ProcessFilter(
            target_path=args.filter_path,
            is_directory=is_dir
        )

    # Initialize components
    protocol_analyzer = ProtocolAnalyzer()
    process_correlator = ProcessCorrelator(process_filter)
    stats = Statistics() if args.stats else None

    # Initialize exporter
    exporter: Optional[Exporter] = None
    if args.export_file:
        export_format = None
        if args.export_format:
            export_format = ExportFormat.JSON if args.export_format == "json" else ExportFormat.CSV

        exporter = Exporter(args.export_file, export_format)

    # Print banner
    protocol_list = list(include_protocols) if include_protocols else None
    display.print_banner(
        filter_path=args.filter_path,
        protocols=protocol_list
    )

    # Print header
    if not args.compact:
        display.print_header()

    # Timing for refreshes
    last_pid_refresh = 0.0
    last_filter_refresh = 0.0
    last_stats_display = 0.0
    refresh_interval = max(0.05, args.refresh)

    try:
        # Initialize capture
        capture = PacketCapture(include_loopback=not args.no_loopback)
        capture.start()

        # Initial refresh
        process_correlator.refresh()
        if process_filter:
            process_correlator.refresh_allowed_pids()

        # Main capture loop
        for packet in capture.capture():
            current_time = time.time()

            # Refresh PID map periodically
            if current_time - last_pid_refresh >= refresh_interval:
                process_correlator.refresh()
                last_pid_refresh = current_time

            # Refresh allowed PIDs for filtered captures
            if process_filter and current_time - last_filter_refresh >= 1.0:
                process_correlator.refresh_allowed_pids()
                last_filter_refresh = current_time

            # Look up process
            process = process_correlator.lookup(
                packet.protocol,
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port
            )

            # Check process filter
            if process_filter:
                pid = process.pid if process else None
                if not process_correlator.is_pid_allowed(pid):
                    continue

            # Identify service and application protocol
            service = protocol_analyzer.identify_service(packet.src_port, packet.dst_port)
            app_info = protocol_analyzer.classify(
                packet.protocol,
                packet.src_port,
                packet.dst_port,
                packet.payload
            )

            # Apply protocol filters
            app_protocol = app_info.protocol if app_info else None
            if not should_include_packet(packet, app_protocol, include_protocols, exclude_protocols):
                continue

            # Update statistics
            if stats:
                stats.record_packet(packet, process)

            # Export packet
            if exporter:
                exporter.write_packet(packet, process, service, app_info)

            # Display packet
            display.print_packet(packet, process, service, app_info)

            # Periodic stats display
            if stats and current_time - last_stats_display >= args.stats_interval:
                display.print_stats_panel(stats)
                last_stats_display = current_time

    except PermissionError as e:
        display.print_error(
            "Administrator privileges required.\n"
            "Please run this program as Administrator."
        )
        return 1

    except KeyboardInterrupt:
        pass

    except Exception as e:
        display.print_error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    finally:
        # Cleanup
        if exporter:
            exporter.close()
            display.print_info(f"Exported to: {args.export_file}")

        display.print_exit_message()

    return 0


if __name__ == "__main__":
    sys.exit(main())
