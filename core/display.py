"""
Display module for ProcShark.

Provides rich terminal UI for displaying captured network traffic
with colored output, tables, and status information.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.style import Style

if TYPE_CHECKING:
    from core.capture import PacketInfo
    from core.protocols import ProtocolInfo
    from core.process import ProcessInfo
    from core.stats import Statistics


# Color scheme for protocols
PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "green",
    "IP": "white",
}

# Color scheme for services
SERVICE_COLORS = {
    "HTTP": "bright_blue",
    "HTTPS": "bright_green",
    "DNS": "yellow",
    "SSH": "magenta",
    "RDP": "red",
    "SMB": "red",
    "SMTP": "bright_magenta",
    "FTP": "bright_cyan",
    "MYSQL": "bright_yellow",
    "POSTGRES": "bright_yellow",
    "REDIS": "bright_red",
    "unknown": "dim",
}

# Color scheme for directions
DIRECTION_COLORS = {
    "IN": "green",
    "OUT": "blue",
}


class Display:
    """
    Rich terminal display for ProcShark.

    Provides colored output with tables, status bars, and
    optional live updating display.
    """

    def __init__(
        self,
        show_payload: bool = True,
        max_payload: int = 1024,
        use_color: bool = True,
        compact: bool = False
    ) -> None:
        """
        Initialize the display.

        Args:
            show_payload: Whether to show packet payload
            max_payload: Maximum payload bytes to display
            use_color: Whether to use colored output
            compact: Use compact single-line output
        """
        self._show_payload = show_payload
        self._max_payload = max_payload
        self._use_color = use_color
        self._compact = compact
        self._console = Console(force_terminal=True, color_system="auto" if use_color else None)
        self._start_time = datetime.now()
        self._packet_count = 0

    @property
    def console(self) -> Console:
        """Get the Rich console instance."""
        return self._console

    def print_banner(
        self,
        filter_path: Optional[str] = None,
        protocols: Optional[list[str]] = None
    ) -> None:
        """
        Print the startup banner.

        Args:
            filter_path: Process filter path if active
            protocols: Protocol filters if active
        """
        banner_text = "[bold cyan]ProcShark[/] - Network Traffic Analyzer with Process Correlation"

        info_lines = []
        if filter_path:
            info_lines.append(f"[yellow]Filter:[/] {filter_path}")
        if protocols:
            info_lines.append(f"[yellow]Protocols:[/] {', '.join(protocols)}")
        info_lines.append("[dim]Requires Administrator privileges. Press Ctrl+C to stop.[/]")

        panel = Panel(
            "\n".join([banner_text, ""] + info_lines),
            title="[bold white]Starting Capture[/]",
            border_style="cyan",
        )
        self._console.print(panel)
        self._console.print()

    def print_header(self) -> None:
        """Print the table header."""
        header = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        header.add_column("Time", style="dim", width=12)
        header.add_column("Dir", width=3)
        header.add_column("Proto", width=5)
        header.add_column("Flags", width=12)
        header.add_column("Source", width=24)
        header.add_column("Destination", width=24)
        header.add_column("Size", justify="right", width=6)
        header.add_column("Service", width=8)
        header.add_column("Process", width=20)
        header.add_column("Application", no_wrap=False)

        # Add empty row just to show headers
        header.add_row("─" * 12, "───", "─────", "─" * 12, "─" * 24, "─" * 24, "──────", "────────", "─" * 20, "─" * 30)

        self._console.print(header)

    def format_direction(self, direction: str) -> Text:
        """Format direction with color."""
        color = DIRECTION_COLORS.get(direction, "white")
        return Text(direction, style=color)

    def format_protocol(self, protocol: str) -> Text:
        """Format protocol with color."""
        color = PROTOCOL_COLORS.get(protocol, "white")
        return Text(protocol, style=color)

    def format_service(self, service: str) -> Text:
        """Format service with color."""
        color = SERVICE_COLORS.get(service, SERVICE_COLORS.get("unknown", "dim"))
        return Text(service, style=color)

    def format_process(self, process: Optional["ProcessInfo"]) -> Text:
        """Format process info with color."""
        if process:
            return Text(str(process), style="bright_white")
        return Text("unknown", style="dim italic")

    def format_flags(self, flags: str) -> Text:
        """Format TCP flags with color coding."""
        if not flags:
            return Text("")

        text = Text()
        for i, flag in enumerate(flags.split(",")):
            if i > 0:
                text.append(",", style="dim")

            if flag == "SYN":
                text.append(flag, style="green bold")
            elif flag == "ACK":
                text.append(flag, style="cyan")
            elif flag == "FIN":
                text.append(flag, style="yellow")
            elif flag == "RST":
                text.append(flag, style="red bold")
            elif flag == "PSH":
                text.append(flag, style="magenta")
            else:
                text.append(flag)

        return text

    def format_application(self, app_info: Optional["ProtocolInfo"]) -> Text:
        """Format application layer info."""
        if not app_info:
            return Text("")

        style = "bright_green" if app_info.is_encrypted else "bright_blue"
        return Text(app_info.description, style=style)

    def print_packet(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> None:
        """
        Print a captured packet.

        Args:
            packet: Captured packet information
            process: Associated process info
            service: Identified service name
            app_info: Application layer protocol info
        """
        self._packet_count += 1

        if self._compact:
            self._print_compact(packet, process, service, app_info)
        else:
            self._print_full(packet, process, service, app_info)

    def _print_compact(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> None:
        """Print packet in compact single-line format."""
        parts = [
            f"[dim]{packet.timestamp_str}[/]",
            f"[{DIRECTION_COLORS.get(packet.direction, 'white')}]{packet.direction}[/]",
            f"[{PROTOCOL_COLORS.get(packet.protocol, 'white')}]{packet.protocol}[/]",
            f"{packet.source} -> {packet.destination}",
            f"[dim]{packet.size}B[/]",
            f"[{SERVICE_COLORS.get(service, 'dim')}]{service}[/]",
            str(process) if process else "[dim]unknown[/]",
        ]

        if app_info:
            parts.append(f"[bright_blue]{app_info.description}[/]")

        self._console.print(" | ".join(parts))

    def _print_full(
        self,
        packet: "PacketInfo",
        process: Optional["ProcessInfo"],
        service: str,
        app_info: Optional["ProtocolInfo"]
    ) -> None:
        """Print packet in full format with payload."""
        # Main row
        row_parts = [
            Text(packet.timestamp_str, style="dim"),
            self.format_direction(packet.direction),
            self.format_protocol(packet.protocol),
            self.format_flags(packet.tcp_flags),
            Text(packet.source),
            Text(packet.destination),
            Text(str(packet.size), style="dim"),
            self.format_service(service),
            self.format_process(process),
            self.format_application(app_info),
        ]

        # Build the line manually for better control
        line = Text()
        widths = [12, 3, 5, 12, 24, 24, 6, 8, 20, 40]

        for i, (part, width) in enumerate(zip(row_parts, widths)):
            if i > 0:
                line.append(" ")

            if isinstance(part, Text):
                # Truncate if needed
                text_str = part.plain[:width] if len(part.plain) > width else part.plain
                styled = Text(text_str.ljust(width))
                styled.stylize(part.style or Style())
                line.append_text(styled)
            else:
                line.append(str(part)[:width].ljust(width))

        self._console.print(line)

        # Payload display
        if self._show_payload and packet.payload:
            self._print_payload(packet)

    def _print_payload(self, packet: "PacketInfo") -> None:
        """Print packet payload in hex and ASCII format."""
        payload_len = len(packet.payload)
        hex_data = packet.payload_hex(self._max_payload)
        ascii_data = packet.payload_ascii(self._max_payload)

        # Hex line
        hex_line = Text()
        hex_line.append(" " * 12)  # Indent
        hex_line.append(f"payload_hex({payload_len}B): ", style="dim")
        hex_line.append(hex_data, style="bright_black")
        self._console.print(hex_line)

        # ASCII line
        ascii_line = Text()
        ascii_line.append(" " * 12)  # Indent
        ascii_line.append(f"payload_ascii({payload_len}B): ", style="dim")
        ascii_line.append(ascii_data, style="bright_black")
        self._console.print(ascii_line)

    def print_stats_panel(self, stats: "Statistics") -> None:
        """
        Print a statistics panel.

        Args:
            stats: Statistics object with current data
        """
        elapsed = (datetime.now() - self._start_time).total_seconds()

        lines = [
            f"[bold]Packets:[/] {stats.total_packets:,}",
            f"[bold]Bytes:[/] {stats.total_bytes:,}",
            f"[bold]Rate:[/] {stats.packets_per_second:.1f} pkt/s | {stats.bandwidth_str}",
            "",
            "[bold]Protocols:[/]",
        ]

        for proto, count in stats.protocol_counts.items():
            lines.append(f"  [{PROTOCOL_COLORS.get(proto, 'white')}]{proto}[/]: {count:,}")

        if stats.top_processes:
            lines.append("")
            lines.append("[bold]Top Processes:[/]")
            for proc, count in stats.top_processes[:5]:
                lines.append(f"  {proc}: {count:,}")

        panel = Panel(
            "\n".join(lines),
            title=f"[bold]Statistics[/] [dim](elapsed: {elapsed:.0f}s)[/]",
            border_style="blue",
        )
        self._console.print(panel)

    def print_error(self, message: str) -> None:
        """Print an error message."""
        self._console.print(f"[bold red]Error:[/] {message}")

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self._console.print(f"[bold yellow]Warning:[/] {message}")

    def print_info(self, message: str) -> None:
        """Print an info message."""
        self._console.print(f"[bold blue]Info:[/] {message}")

    def print_success(self, message: str) -> None:
        """Print a success message."""
        self._console.print(f"[bold green]Success:[/] {message}")

    def clear(self) -> None:
        """Clear the terminal screen."""
        self._console.clear()

    def print_exit_message(self) -> None:
        """Print exit message with summary."""
        elapsed = (datetime.now() - self._start_time).total_seconds()
        self._console.print()
        self._console.print(
            f"[bold cyan]Capture stopped.[/] "
            f"Captured [bold]{self._packet_count:,}[/] packets "
            f"in [bold]{elapsed:.1f}[/] seconds."
        )
