"""
Network Traffic Analysis Tool
===============================
Analyzes network traffic from PCAP files or live captures using Scapy.
Provides statistics, protocol breakdown, top talkers, anomaly detection,
and exports results to CSV / JSON / PDF.

Dependencies:
    pip install scapy tabulate colorama reportlab

Usage:
    python network_traffic_analysis.py --demo
    python network_traffic_analysis.py --file capture.pcap
    python network_traffic_analysis.py --live eth0 --duration 30
    python network_traffic_analysis.py --demo --out-pdf report.pdf
"""

import argparse
import csv
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ─── Optional rich imports ────────────────────────────────────────────────────
try:
    from scapy.all import (
        ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP,
        PcapReader, sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable, Image, PageBreak, Paragraph, SimpleDocTemplate,
        Spacer, Table, TableStyle,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ─── Colour helpers ───────────────────────────────────────────────────────────

def _c(color: str, text: str) -> str:
    if not COLORAMA_AVAILABLE:
        return text
    _map = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN, "blue": Fore.BLUE,
        "bold": Style.BRIGHT, "reset": Style.RESET_ALL,
    }
    return f"{_map.get(color, '')}{text}{Style.RESET_ALL}"


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class PacketRecord:
    timestamp:  float
    src_ip:     str = ""
    dst_ip:     str = ""
    src_port:   int = 0
    dst_port:   int = 0
    protocol:   str = "UNKNOWN"
    length:     int = 0
    flags:      str = ""
    ttl:        int = 0
    dns_query:  str = ""
    dns_answer: str = ""
    icmp_type:  int = -1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = datetime.fromtimestamp(self.timestamp).isoformat()
        return d


@dataclass
class TrafficStats:
    total_packets:      int   = 0
    total_bytes:        int   = 0
    duration_seconds:   float = 0.0
    start_time:         float = 0.0
    end_time:           float = 0.0
    protocol_counts:    Dict[str, int]        = field(default_factory=dict)
    protocol_bytes:     Dict[str, int]        = field(default_factory=dict)
    top_src_ips:        List[Tuple[str, int]] = field(default_factory=list)
    top_dst_ips:        List[Tuple[str, int]] = field(default_factory=list)
    top_src_ports:      List[Tuple[int, int]] = field(default_factory=list)
    top_dst_ports:      List[Tuple[int, int]] = field(default_factory=list)
    top_conversations:  List[Tuple[Tuple, int]] = field(default_factory=list)
    top_dns_queries:    List[Tuple[str, int]] = field(default_factory=list)
    anomalies:          List[str]             = field(default_factory=list)
    packets_per_second: float = 0.0
    bytes_per_second:   float = 0.0
    syn_count:  int = 0
    fin_count:  int = 0
    rst_count:  int = 0
    ack_count:  int = 0


# ─── Core analyser ────────────────────────────────────────────────────────────

class NetworkTrafficAnalyser:
    KNOWN_PORTS: Dict[int, str] = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
        27017: "MongoDB",
    }

    def __init__(self, top_n: int = 10):
        self.top_n = top_n
        self.packets: List[PacketRecord] = []

    # ── Ingestion ──────────────────────────────────────────────────────────────

    def load_pcap(self, path: str) -> int:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required. pip install scapy")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"PCAP not found: {path}")
        count = 0
        print(_c("cyan", f"[*] Reading: {path}"))
        with PcapReader(path) as reader:
            for pkt in reader:
                rec = self._parse_scapy_packet(pkt)
                if rec:
                    self.packets.append(rec)
                    count += 1
        print(_c("green", f"[+] Loaded {count:,} packets."))
        return count

    def capture_live(self, iface: str, duration: int = 30,
                     packet_count: int = 0) -> int:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy required for live capture.")
        print(_c("cyan", f"[*] Capturing on {iface} for {duration}s …"))
        captured: list = []

        def _handler(pkt):
            rec = self._parse_scapy_packet(pkt)
            if rec:
                captured.append(rec)

        sniff(iface=iface, prn=_handler, timeout=duration,
              count=packet_count or 0, store=False)
        self.packets.extend(captured)
        print(_c("green", f"[+] Captured {len(captured):,} packets."))
        return len(captured)

    def load_demo(self, n: int = 500) -> int:
        print(_c("yellow", f"[*] Generating {n} synthetic packets …"))
        random.seed(42)
        src_pool = [f"192.168.1.{i}" for i in range(1, 20)]
        dst_pool = (
            [f"10.0.0.{i}" for i in range(1, 10)] +
            ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.217.14.206"]
        )
        proto_pool    = ["TCP", "UDP", "ICMP", "DNS", "ARP"]
        proto_weights = [50, 20, 10, 15, 5]
        base_ts = time.time() - n * 0.1

        for i in range(n):
            proto    = random.choices(proto_pool, proto_weights)[0]
            src_ip   = random.choice(src_pool)
            dst_ip   = random.choice(dst_pool)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(
                list(self.KNOWN_PORTS.keys()) + [random.randint(1, 1024)])
            flags = ""
            dns_q = ""

            if proto == "TCP":
                flags = random.choice(["S", "SA", "A", "FA", "R", "PA"])
            elif proto == "DNS":
                dns_q = random.choice([
                    "google.com", "example.com", "github.com",
                    "api.service.internal", "cdn.vendor.net",
                ])
                dst_port = 53

            self.packets.append(PacketRecord(
                timestamp=base_ts + i * 0.1 + random.uniform(0, 0.05),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=proto, length=random.randint(40, 1500),
                flags=flags, ttl=random.randint(32, 128),
                dns_query=dns_q,
            ))

        # Inject anomaly bursts (port scan simulation)
        for _ in range(5):
            src = random.choice(src_pool)
            for _ in range(20):
                self.packets.append(PacketRecord(
                    timestamp=base_ts + random.uniform(0, 1),
                    src_ip=src, dst_ip=random.choice(dst_pool),
                    src_port=random.randint(1024, 65535),
                    dst_port=random.randint(1, 1024),
                    protocol="TCP", length=60, flags="S", ttl=64,
                ))

        self.packets.sort(key=lambda p: p.timestamp)
        print(_c("green", f"[+] Generated {len(self.packets):,} packets."))
        return len(self.packets)

    # ── Packet parsing (Scapy) ────────────────────────────────────────────────

    @staticmethod
    def _parse_scapy_packet(pkt) -> Optional[PacketRecord]:
        try:
            rec = PacketRecord(timestamp=float(pkt.time), length=len(pkt))
            if pkt.haslayer(IP):
                ip = pkt[IP]
                rec.src_ip = ip.src
                rec.dst_ip = ip.dst
                rec.ttl    = ip.ttl
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    rec.src_port = tcp.sport
                    rec.dst_port = tcp.dport
                    rec.protocol = "TCP"
                    flag_map = {0x01: "F", 0x02: "S", 0x04: "R",
                                0x08: "P", 0x10: "A", 0x20: "U"}
                    rec.flags = "".join(v for k, v in flag_map.items()
                                        if tcp.flags & k)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    rec.src_port = udp.sport
                    rec.dst_port = udp.dport
                    rec.protocol = "UDP"
                    if pkt.haslayer(DNS):
                        rec.protocol = "DNS"
                        dns = pkt[DNS]
                        if dns.qr == 0 and pkt.haslayer(DNSQR):
                            rec.dns_query = pkt[DNSQR].qname.decode(
                                errors="replace").rstrip(".")
                        elif dns.qr == 1 and pkt.haslayer(DNSRR):
                            rec.dns_answer = (
                                pkt[DNSRR].rdata
                                if isinstance(pkt[DNSRR].rdata, str)
                                else str(pkt[DNSRR].rdata)
                            )
                elif pkt.haslayer(ICMP):
                    rec.protocol  = "ICMP"
                    rec.icmp_type = pkt[ICMP].type
            elif pkt.haslayer(ARP):
                arp = pkt[ARP]
                rec.src_ip   = arp.psrc
                rec.dst_ip   = arp.pdst
                rec.protocol = "ARP"
            else:
                rec.protocol = "OTHER"
            return rec
        except Exception:
            return None

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyse(self) -> TrafficStats:
        if not self.packets:
            raise ValueError("No packets loaded.")

        stats = TrafficStats()
        stats.total_packets    = len(self.packets)
        stats.total_bytes      = sum(p.length for p in self.packets)
        stats.start_time       = self.packets[0].timestamp
        stats.end_time         = self.packets[-1].timestamp
        stats.duration_seconds = max(stats.end_time - stats.start_time, 0.001)
        stats.packets_per_second = stats.total_packets / stats.duration_seconds
        stats.bytes_per_second   = stats.total_bytes   / stats.duration_seconds

        proto_cnt   = Counter(p.protocol for p in self.packets)
        proto_bytes = defaultdict(int)
        for p in self.packets:
            proto_bytes[p.protocol] += p.length

        stats.protocol_counts = dict(proto_cnt.most_common())
        stats.protocol_bytes  = dict(proto_bytes)

        src_cnt = Counter(p.src_ip   for p in self.packets if p.src_ip)
        dst_cnt = Counter(p.dst_ip   for p in self.packets if p.dst_ip)
        sp_cnt  = Counter(p.src_port for p in self.packets if p.src_port)
        dp_cnt  = Counter(p.dst_port for p in self.packets if p.dst_port)

        stats.top_src_ips   = src_cnt.most_common(self.top_n)
        stats.top_dst_ips   = dst_cnt.most_common(self.top_n)
        stats.top_src_ports = sp_cnt.most_common(self.top_n)
        stats.top_dst_ports = dp_cnt.most_common(self.top_n)

        conv = Counter((p.src_ip, p.dst_ip)
                       for p in self.packets if p.src_ip and p.dst_ip)
        stats.top_conversations = conv.most_common(self.top_n)

        dns_q = Counter(p.dns_query for p in self.packets if p.dns_query)
        stats.top_dns_queries = dns_q.most_common(self.top_n)

        for p in self.packets:
            f = p.flags
            if "S" in f: stats.syn_count += 1
            if "F" in f: stats.fin_count += 1
            if "R" in f: stats.rst_count += 1
            if "A" in f: stats.ack_count += 1

        stats.anomalies = self._detect_anomalies(stats)
        return stats

    def _detect_anomalies(self, stats: TrafficStats) -> List[str]:
        anomalies: List[str] = []

        src_dports: Dict[str, set] = defaultdict(set)
        for p in self.packets:
            if p.protocol == "TCP" and p.src_ip:
                src_dports[p.src_ip].add(p.dst_port)
        for src, ports in src_dports.items():
            if len(ports) > 20:
                anomalies.append(
                    f"Possible port scan from {src} "
                    f"({len(ports)} distinct destination ports)"
                )

        tcp_pkts = stats.protocol_counts.get("TCP", 0)
        if tcp_pkts and stats.rst_count / tcp_pkts > 0.15:
            anomalies.append(
                f"High TCP RST rate: {stats.rst_count}/{tcp_pkts} "
                f"({100*stats.rst_count/tcp_pkts:.1f}%) — possible scan/rejection"
            )
        if tcp_pkts and stats.syn_count / tcp_pkts > 0.5:
            anomalies.append(
                f"High SYN ratio: {stats.syn_count}/{tcp_pkts} "
                f"({100*stats.syn_count/tcp_pkts:.1f}%) — possible SYN flood"
            )

        for ip, cnt in stats.top_dst_ips[:5]:
            if cnt > stats.total_packets * 0.3:
                anomalies.append(
                    f"Destination {ip} receives {cnt:,} packets "
                    f"({100*cnt/stats.total_packets:.1f}% of total)"
                )

        large = [p for p in self.packets if p.length > 8000]
        if large:
            anomalies.append(
                f"{len(large)} oversized packets detected (>8000 bytes)"
            )

        return anomalies if anomalies else ["No anomalies detected."]

    # ── Terminal report ───────────────────────────────────────────────────────

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def _table(self, headers, rows):
        if TABULATE_AVAILABLE:
            return tabulate(rows, headers=headers, tablefmt="rounded_outline")
        col_w = [max(len(str(r[i])) for r in ([headers] + rows))
                 for i in range(len(headers))]
        sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
        def row_str(r):
            return "|" + "|".join(
                f" {str(v):<{col_w[i]}} " for i, v in enumerate(r)) + "|"
        lines = [sep, row_str(headers), sep] + \
                [row_str(r) for r in rows] + [sep]
        return "\n".join(lines)

    def print_report(self, stats: TrafficStats) -> None:
        W = 60
        print("\n" + _c("bold", "=" * W))
        print(_c("bold", _c("cyan", "  NETWORK TRAFFIC ANALYSIS REPORT")))
        print(_c("bold", "=" * W))
        start = datetime.fromtimestamp(stats.start_time).strftime("%Y-%m-%d %H:%M:%S")
        end   = datetime.fromtimestamp(stats.end_time  ).strftime("%Y-%m-%d %H:%M:%S")
        print(_c("yellow", "\n── Summary ──────────────────────────────────────"))
        print(f"  Capture window  : {start}  →  {end}")
        print(f"  Duration        : {stats.duration_seconds:.2f} s")
        print(f"  Total packets   : {stats.total_packets:,}")
        print(f"  Total bytes     : {self._fmt_bytes(stats.total_bytes)}")
        print(f"  Packets/sec     : {stats.packets_per_second:.1f}")
        print(f"  Throughput      : {self._fmt_bytes(int(stats.bytes_per_second))}/s")

        print(_c("yellow", "\n── Protocol Breakdown ───────────────────────────"))
        rows = []
        for proto, cnt in sorted(stats.protocol_counts.items(),
                                  key=lambda x: x[1], reverse=True):
            pct = 100 * cnt / stats.total_packets
            byt = stats.protocol_bytes.get(proto, 0)
            rows.append([proto, cnt, f"{pct:.1f}%", self._fmt_bytes(byt)])
        print(self._table(["Protocol", "Packets", "Share", "Bytes"], rows))

        if stats.syn_count or stats.fin_count or stats.rst_count:
            print(_c("yellow", "\n── TCP Flag Summary ─────────────────────────────"))
            print(self._table(["Flag", "Count"], [
                ["SYN", stats.syn_count], ["FIN", stats.fin_count],
                ["RST", stats.rst_count], ["ACK", stats.ack_count],
            ]))

        print(_c("yellow", "\n── Top Source IPs ───────────────────────────────"))
        print(self._table(["IP Address", "Packets", "Share"],
            [[ip, cnt, f"{100*cnt/stats.total_packets:.1f}%"]
             for ip, cnt in stats.top_src_ips]))

        print(_c("yellow", "\n── Top Destination IPs ──────────────────────────"))
        print(self._table(["IP Address", "Packets", "Share"],
            [[ip, cnt, f"{100*cnt/stats.total_packets:.1f}%"]
             for ip, cnt in stats.top_dst_ips]))

        print(_c("yellow", "\n── Top Destination Ports ────────────────────────"))
        print(self._table(["Port", "Service", "Packets"],
            [[port, self.KNOWN_PORTS.get(port, "Unknown"), cnt]
             for port, cnt in stats.top_dst_ports]))

        print(_c("yellow", "\n── Top Conversations ────────────────────────────"))
        print(self._table(["Source", "Destination", "Packets"],
            [[src, dst, cnt] for (src, dst), cnt in stats.top_conversations]))

        if stats.top_dns_queries:
            print(_c("yellow", "\n── Top DNS Queries ──────────────────────────────"))
            print(self._table(["Domain", "Queries"],
                [[q, cnt] for q, cnt in stats.top_dns_queries]))

        print(_c("yellow", "\n── Anomaly Detection ────────────────────────────"))
        for a in stats.anomalies:
            col = "red" if "possible" in a.lower() or "high" in a.lower() else "green"
            print(f"  {_c(col, '!' if col == 'red' else 'v')}  {a}")

        print("\n" + _c("bold", "=" * W) + "\n")

    # ── CSV / JSON export ─────────────────────────────────────────────────────

    def export_csv(self, path: str) -> None:
        if not self.packets:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self.packets[0].to_dict().keys())
            writer.writeheader()
            for p in self.packets:
                writer.writerow(p.to_dict())
        print(_c("green", f"[+] CSV exported -> {path}"))

    def export_json(self, path: str, stats: TrafficStats) -> None:
        def _s(obj):
            if isinstance(obj, dict):   return {k: _s(v) for k, v in obj.items()}
            if isinstance(obj, list):   return [_s(i) for i in obj]
            if isinstance(obj, tuple):  return list(obj)
            if isinstance(obj, float):  return round(obj, 4)
            return obj
        payload = _s(asdict(stats))
        payload["start_time"] = datetime.fromtimestamp(stats.start_time).isoformat()
        payload["end_time"]   = datetime.fromtimestamp(stats.end_time  ).isoformat()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(_c("green", f"[+] JSON exported -> {path}"))

    # ── PDF export ────────────────────────────────────────────────────────────

    def export_pdf(self, path: str, stats: TrafficStats) -> None:
        """Generate a professional multi-section PDF report."""
        if not REPORTLAB_AVAILABLE:
            print(_c("red", "[!] reportlab not installed. pip install reportlab"))
            return

        # ── Palette ──────────────────────────────────────────────────────────
        NAVY    = colors.HexColor("#0D1B2A")
        BLUE    = colors.HexColor("#1B4F8A")
        ACCENT  = colors.HexColor("#2E86C1")
        LIGHT   = colors.HexColor("#EBF5FB")
        ALERT   = colors.HexColor("#C0392B")
        WARN    = colors.HexColor("#E67E22")
        OK      = colors.HexColor("#1E8449")
        WHITE   = colors.white
        GREY    = colors.HexColor("#BDC3C7")
        MIDGREY = colors.HexColor("#7F8C8D")

        # ── Styles ────────────────────────────────────────────────────────────
        base = getSampleStyleSheet()

        def ps(name, parent="Normal", **kw) -> ParagraphStyle:
            return ParagraphStyle(name, parent=base[parent], **kw)

        sTitle = ps("rTitle", "Title",
                    fontSize=28, textColor=WHITE, alignment=TA_CENTER,
                    spaceAfter=4, fontName="Helvetica-Bold")
        sSubtitle = ps("rSubtitle",
                       fontSize=11, textColor=GREY, alignment=TA_CENTER,
                       spaceAfter=2, fontName="Helvetica")
        sH1 = ps("rH1", "Heading1",
                 fontSize=14, textColor=WHITE, fontName="Helvetica-Bold",
                 spaceBefore=14, spaceAfter=6)
        sH2 = ps("rH2", "Heading2",
                 fontSize=11, textColor=BLUE, fontName="Helvetica-Bold",
                 spaceBefore=10, spaceAfter=4)
        sBody = ps("rBody",
                   fontSize=9, textColor=NAVY, leading=14,
                   fontName="Helvetica")
        sAlert = ps("rAlert",
                    fontSize=9, textColor=ALERT, leading=13,
                    fontName="Helvetica-Bold")
        sOK    = ps("rOK",
                    fontSize=9, textColor=OK, leading=13,
                    fontName="Helvetica")
        sSmall = ps("rSmall",
                    fontSize=7.5, textColor=MIDGREY, leading=11,
                    fontName="Helvetica")
        sMono  = ps("rMono",
                    fontSize=8, textColor=NAVY, leading=12,
                    fontName="Courier")

        # ── Helpers ───────────────────────────────────────────────────────────
        fmt = self._fmt_bytes

        def hline(col=ACCENT, thickness=0.8):
            return HRFlowable(width="100%", thickness=thickness,
                              color=col, spaceAfter=6, spaceBefore=2)

        def section_header(text: str):
            """Dark banner heading."""
            tbl = Table([[Paragraph(text, sH1)]], colWidths=["100%"])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("ROUNDEDCORNERS", [4]),
            ]))
            return tbl

        def data_table(headers, rows, col_widths=None, zebra=True):
            """Styled data table with header row."""
            data = [headers] + rows
            t = Table(data, colWidths=col_widths, repeatRows=1)
            style = [
                # Header
                ("BACKGROUND",   (0, 0), (-1, 0), BLUE),
                ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, 0), 9),
                ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
                ("TOPPADDING",   (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING",(0, 0), (-1, 0), 6),
                # Body
                ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE",     (0, 1), (-1, -1), 8.5),
                ("TEXTCOLOR",    (0, 1), (-1, -1), NAVY),
                ("TOPPADDING",   (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 1), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                # Grid
                ("GRID",         (0, 0), (-1, -1), 0.4, GREY),
                ("LINEBELOW",    (0, 0), (-1, 0), 1.5, ACCENT),
            ]
            if zebra:
                for i in range(1, len(data)):
                    if i % 2 == 0:
                        style.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
            t.setStyle(TableStyle(style))
            return t

        def kv_card(items: List[Tuple[str, str]]):
            """Key-value summary card."""
            rows = [[Paragraph(f"<b>{k}</b>", sBody),
                     Paragraph(v, sBody)] for k, v in items]
            t = Table(rows, colWidths=[5.5 * cm, 9.5 * cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), LIGHT),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("GRID",         (0, 0), (-1, -1), 0.3, GREY),
                ("LINEAFTER",    (0, 0), (0, -1), 1, ACCENT),
            ]))
            return t

        # ── Pie chart ─────────────────────────────────────────────────────────
        def proto_pie(proto_counts: dict, size=160) -> Drawing:
            items = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
            labels = [x[0] for x in items]
            data   = [x[1] for x in items]
            palette = [BLUE, ACCENT, WARN, OK, ALERT,
                       colors.HexColor("#8E44AD"),
                       colors.HexColor("#17A589"),
                       MIDGREY]

            d = Drawing(size, size)
            pie = Pie()
            pie.x      = size // 2 - 55
            pie.y      = size // 2 - 55
            pie.width  = 110
            pie.height = 110
            pie.data   = data
            pie.labels = [f"{l} ({100*v/sum(data):.0f}%)"
                          for l, v in zip(labels, data)]
            pie.sideLabels    = True
            pie.slices.strokeWidth = 0.5
            pie.slices.strokeColor = WHITE
            for i, col in enumerate(palette[:len(data)]):
                pie.slices[i].fillColor = col
            d.add(pie)
            return d

        # ── Bar chart (top IPs) ───────────────────────────────────────────────
        def ip_bar(top_ips: list, width=380, height=120) -> Drawing:
            if not top_ips:
                return Drawing(width, height)
            items  = top_ips[:8]
            labels = [ip for ip, _ in items]
            values = [cnt for _, cnt in items]

            d = Drawing(width, height)
            bc = VerticalBarChart()
            bc.x         = 45
            bc.y         = 20
            bc.width     = width - 60
            bc.height    = height - 30
            bc.data      = [values]
            bc.bars[0].fillColor = ACCENT
            bc.bars[0].strokeColor = None
            bc.categoryAxis.categoryNames   = labels
            bc.categoryAxis.labels.angle    = 30
            bc.categoryAxis.labels.fontSize = 7
            bc.categoryAxis.labels.dy       = -8
            bc.valueAxis.labels.fontSize    = 7
            bc.valueAxis.forceZero          = True
            bc.groupSpacing = 2
            d.add(bc)
            return d

        # ── Page template with header/footer ──────────────────────────────────
        page_w, page_h = A4
        margin = 1.8 * cm
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def on_page(canvas, doc):
            canvas.saveState()
            # Top stripe
            canvas.setFillColor(NAVY)
            canvas.rect(0, page_h - 1.1 * cm, page_w, 1.1 * cm, fill=1, stroke=0)
            canvas.setFillColor(WHITE)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(margin, page_h - 0.7 * cm,
                              "Network Traffic Analysis Report")
            canvas.setFont("Helvetica", 7)
            canvas.drawRightString(page_w - margin, page_h - 0.7 * cm,
                                   f"Generated: {generated_at}")
            # Bottom stripe
            canvas.setFillColor(NAVY)
            canvas.rect(0, 0, page_w, 0.9 * cm, fill=1, stroke=0)
            canvas.setFillColor(GREY)
            canvas.setFont("Helvetica", 7)
            canvas.drawCentredString(page_w / 2, 0.32 * cm,
                                     f"Page {doc.page}  |  CONFIDENTIAL")
            canvas.restoreState()

        # ── Document ──────────────────────────────────────────────────────────
        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=margin, rightMargin=margin,
            topMargin=1.6 * cm, bottomMargin=1.4 * cm,
            title="Network Traffic Analysis Report",
            author="NetworkTrafficAnalyser",
        )

        story = []

        # ══════════════════════════════════════════════════════════════════════
        # COVER PAGE
        # ══════════════════════════════════════════════════════════════════════
        story.append(Spacer(1, 2.5 * cm))

        # Banner
        cover_tbl = Table([[Paragraph("NETWORK TRAFFIC", sTitle)],
                           [Paragraph("ANALYSIS REPORT", sTitle)]],
                          colWidths=["100%"])
        cover_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), NAVY),
            ("TOPPADDING",   (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 14),
            ("LEFTPADDING",  (0, 0), (-1, -1), 20),
            ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ]))
        story.append(cover_tbl)
        story.append(Spacer(1, 0.5 * cm))
        story.append(hline(ACCENT, 3))
        story.append(Spacer(1, 0.3 * cm))

        start_dt = datetime.fromtimestamp(stats.start_time).strftime("%Y-%m-%d %H:%M:%S")
        end_dt   = datetime.fromtimestamp(stats.end_time  ).strftime("%Y-%m-%d %H:%M:%S")

        story.append(Paragraph(f"Capture Period:  {start_dt}  —  {end_dt}", sSubtitle))
        story.append(Paragraph(f"Generated:  {generated_at}", sSubtitle))
        story.append(Spacer(1, 1.5 * cm))

        # Cover summary cards
        cover_data = [
            ["Total Packets",    f"{stats.total_packets:,}"],
            ["Total Data",       fmt(stats.total_bytes)],
            ["Duration",         f"{stats.duration_seconds:.2f} seconds"],
            ["Avg Packet Rate",  f"{stats.packets_per_second:.1f} pkt/s"],
            ["Avg Throughput",   f"{fmt(int(stats.bytes_per_second))}/s"],
            ["Protocols Seen",   str(len(stats.protocol_counts))],
        ]
        cover_t = Table(
            [[Paragraph(f"<b>{k}</b>", sBody),
              Paragraph(v, sBody)] for k, v in cover_data],
            colWidths=[6 * cm, 9 * cm],
        )
        cover_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), LIGHT),
            ("TOPPADDING",   (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
            ("LEFTPADDING",  (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("GRID",         (0, 0), (-1, -1), 0.4, GREY),
            ("LINEAFTER",    (0, 0), (0, -1), 2, ACCENT),
            ("FONTNAME",     (1, 0), (1, -1), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 10),
            ("TEXTCOLOR",    (0, 0), (0, -1), MIDGREY),
            ("TEXTCOLOR",    (1, 0), (1, -1), NAVY),
        ]))
        story.append(cover_t)
        story.append(Spacer(1, 1 * cm))

        anomaly_count = sum(1 for a in stats.anomalies if "possible" in a.lower()
                            or "high" in a.lower() or "oversized" in a.lower())
        status_text = (
            f"<b>ALERT:</b>  {anomaly_count} security concern(s) detected."
            if anomaly_count
            else "<b>STATUS:</b>  No significant anomalies detected."
        )
        status_style = sAlert if anomaly_count else sOK
        status_bg    = colors.HexColor("#FDEDEC") if anomaly_count \
            else colors.HexColor("#EAFAF1")
        status_border = ALERT if anomaly_count else OK

        status_box = Table([[Paragraph(status_text, status_style)]],
                           colWidths=["100%"])
        status_box.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), status_bg),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("LINEAFTER",     (0, 0), (0, -1), 4, status_border),
            ("BOX",           (0, 0), (-1, -1), 0.5, status_border),
        ]))
        story.append(status_box)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 1 — CAPTURE SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("1.  Capture Summary"))
        story.append(Spacer(1, 0.3 * cm))
        story.append(kv_card([
            ("Capture Start",   start_dt),
            ("Capture End",     end_dt),
            ("Duration",        f"{stats.duration_seconds:.2f} s"),
            ("Total Packets",   f"{stats.total_packets:,}"),
            ("Total Data",      fmt(stats.total_bytes)),
            ("Avg Packet Rate", f"{stats.packets_per_second:.1f} pkt/s"),
            ("Avg Throughput",  f"{fmt(int(stats.bytes_per_second))}/s"),
            ("Unique Protocols",str(len(stats.protocol_counts))),
        ]))
        story.append(Spacer(1, 0.5 * cm))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 2 — PROTOCOL BREAKDOWN
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("2.  Protocol Breakdown"))
        story.append(Spacer(1, 0.3 * cm))

        proto_rows = []
        for proto, cnt in sorted(stats.protocol_counts.items(),
                                  key=lambda x: x[1], reverse=True):
            pct = 100 * cnt / stats.total_packets
            byt = stats.protocol_bytes.get(proto, 0)
            bar = "█" * int(pct / 5)
            proto_rows.append([proto, f"{cnt:,}", f"{pct:.1f}%",
                                fmt(byt), bar])

        story.append(data_table(
            ["Protocol", "Packets", "Share", "Bytes", "Distribution"],
            proto_rows,
            col_widths=[3*cm, 3*cm, 2.5*cm, 3*cm, 4.5*cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Protocol Distribution Chart", sH2))
        story.append(proto_pie(stats.protocol_counts, size=200))
        story.append(Spacer(1, 0.3 * cm))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 3 — TCP FLAG ANALYSIS
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("3.  TCP Flag Analysis"))
        story.append(Spacer(1, 0.3 * cm))
        tcp_total = stats.protocol_counts.get("TCP", 0)
        story.append(Paragraph(
            f"Total TCP packets: <b>{tcp_total:,}</b>", sBody))
        story.append(Spacer(1, 0.25 * cm))

        flag_rows = []
        for flag, count in [("SYN", stats.syn_count),
                             ("FIN", stats.fin_count),
                             ("RST", stats.rst_count),
                             ("ACK", stats.ack_count)]:
            pct = (100 * count / tcp_total) if tcp_total else 0
            flag_rows.append([flag, f"{count:,}", f"{pct:.1f}%"])

        story.append(data_table(
            ["Flag", "Count", "% of TCP"],
            flag_rows,
            col_widths=[4*cm, 4*cm, 4*cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 4 — TOP TALKERS
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("4.  Top Talkers"))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Top Source IP Addresses", sH2))
        story.append(data_table(
            ["Rank", "IP Address", "Packets", "Share"],
            [[i+1, ip, f"{cnt:,}", f"{100*cnt/stats.total_packets:.1f}%"]
             for i, (ip, cnt) in enumerate(stats.top_src_ips)],
            col_widths=[1.5*cm, 5.5*cm, 3.5*cm, 3.5*cm],
        ))
        story.append(Spacer(1, 0.3 * cm))
        story.append(ip_bar(stats.top_src_ips))

        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Top Destination IP Addresses", sH2))
        story.append(data_table(
            ["Rank", "IP Address", "Packets", "Share"],
            [[i+1, ip, f"{cnt:,}", f"{100*cnt/stats.total_packets:.1f}%"]
             for i, (ip, cnt) in enumerate(stats.top_dst_ips)],
            col_widths=[1.5*cm, 5.5*cm, 3.5*cm, 3.5*cm],
        ))
        story.append(Spacer(1, 0.3 * cm))
        story.append(ip_bar(stats.top_dst_ips))
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 5 — PORT ANALYSIS
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("5.  Port Analysis"))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Top Destination Ports", sH2))
        story.append(data_table(
            ["Port", "Service", "Packets", "% Total"],
            [[port, self.KNOWN_PORTS.get(port, "Unknown"),
              f"{cnt:,}", f"{100*cnt/stats.total_packets:.1f}%"]
             for port, cnt in stats.top_dst_ports],
            col_widths=[3*cm, 4*cm, 3.5*cm, 3.5*cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Top Source Ports", sH2))
        story.append(data_table(
            ["Port", "Service", "Packets"],
            [[port, self.KNOWN_PORTS.get(port, "Unknown"), f"{cnt:,}"]
             for port, cnt in stats.top_src_ports],
            col_widths=[3*cm, 4*cm, 3.5*cm],
        ))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 6 — CONVERSATIONS
        # ══════════════════════════════════════════════════════════════════════
        story.append(Spacer(1, 0.5 * cm))
        story.append(section_header("6.  Top Conversations"))
        story.append(Spacer(1, 0.3 * cm))
        story.append(data_table(
            ["Rank", "Source IP", "Destination IP", "Packets"],
            [[i+1, src, dst, f"{cnt:,}"]
             for i, ((src, dst), cnt) in enumerate(stats.top_conversations)],
            col_widths=[1.5*cm, 5*cm, 5*cm, 3*cm],
        ))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 7 — DNS QUERIES
        # ══════════════════════════════════════════════════════════════════════
        if stats.top_dns_queries:
            story.append(Spacer(1, 0.5 * cm))
            story.append(section_header("7.  DNS Query Analysis"))
            story.append(Spacer(1, 0.3 * cm))
            story.append(data_table(
                ["Rank", "Domain", "Query Count"],
                [[i+1, domain, f"{cnt:,}"]
                 for i, (domain, cnt) in enumerate(stats.top_dns_queries)],
                col_widths=[1.5*cm, 9*cm, 3.5*cm],
            ))
            story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 8 — ANOMALY DETECTION
        # ══════════════════════════════════════════════════════════════════════
        story.append(section_header("8.  Anomaly Detection"))
        story.append(Spacer(1, 0.4 * cm))

        for idx, anomaly in enumerate(stats.anomalies, 1):
            is_alert = any(kw in anomaly.lower()
                           for kw in ("possible", "high", "oversized"))
            icon   = "[!]" if is_alert else "[OK]"
            colour = ALERT if is_alert else OK
            bg     = colors.HexColor("#FDEDEC") if is_alert \
                else colors.HexColor("#EAFAF1")
            style  = sAlert if is_alert else sOK

            row_tbl = Table(
                [[Paragraph(f"<b>{icon}</b>  {anomaly}", style)]],
                colWidths=["100%"],
            )
            row_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("LINEBEFORE",    (0, 0), (0, -1), 4, colour),
                ("BOX",           (0, 0), (-1, -1), 0.3, GREY),
            ]))
            story.append(row_tbl)
            story.append(Spacer(1, 0.2 * cm))

        story.append(Spacer(1, 0.5 * cm))

        # ── Recommendations ───────────────────────────────────────────────────
        story.append(Paragraph("Recommendations", sH2))
        story.append(hline())
        recs = []
        if any("port scan" in a.lower() for a in stats.anomalies):
            recs.append("Investigate IPs exhibiting port scanning behaviour. "
                        "Consider adding firewall rules or IDS signatures.")
        if any("syn flood" in a.lower() for a in stats.anomalies):
            recs.append("High SYN rates detected. Enable SYN cookies or "
                        "rate-limiting at the perimeter firewall.")
        if any("rst" in a.lower() for a in stats.anomalies):
            recs.append("Elevated RST traffic may indicate rejected connections "
                        "or active scanning. Review ACL policies.")
        if not recs:
            recs.append("Traffic patterns appear normal. Continue routine monitoring.")

        for r in recs:
            story.append(Paragraph(f"• {r}", sBody))
            story.append(Spacer(1, 0.15 * cm))

        # ── Footer note ───────────────────────────────────────────────────────
        story.append(Spacer(1, 1 * cm))
        story.append(hline(GREY, 0.4))
        story.append(Paragraph(
            "This report was automatically generated by the Network Traffic "
            "Analysis Tool. All data is derived from captured packet metadata "
            "and should be reviewed by a qualified network security professional.",
            sSmall,
        ))

        # ── Build ─────────────────────────────────────────────────────────────
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        print(_c("green", f"[+] PDF report -> {path}"))


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Network Traffic Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",   metavar="PATH",
                     help="Path to .pcap / .pcapng file")
    src.add_argument("--live",   metavar="IFACE",
                     help="Live capture interface (e.g. eth0, en0)")
    src.add_argument("--demo",   action="store_true",
                     help="Run on synthetic demo traffic")

    p.add_argument("--duration", type=int, default=30,
                   help="Capture duration in seconds (live mode, default 30)")
    p.add_argument("--count",    type=int, default=500,
                   help="Packet count for demo mode (default 500)")
    p.add_argument("--top",      type=int, default=10,
                   help="Number of top entries to show (default 10)")
    p.add_argument("--out-csv",  metavar="PATH",
                   help="Export packet records to CSV")
    p.add_argument("--out-json", metavar="PATH",
                   help="Export stats summary to JSON")
    p.add_argument("--out-pdf",  metavar="PATH",
                   help="Export full analysis report to PDF")
    return p


def main(argv: Optional[List[str]] = None) -> None:
    args = _build_parser().parse_args(argv)

    analyser = NetworkTrafficAnalyser(top_n=args.top)

    try:
        if args.demo:
            analyser.load_demo(n=args.count)
        elif args.file:
            analyser.load_pcap(args.file)
        else:
            analyser.capture_live(args.live, duration=args.duration)
    except (FileNotFoundError, RuntimeError) as exc:
        print(_c("red", f"[ERROR] {exc}"))
        sys.exit(1)

    stats = analyser.analyse()
    analyser.print_report(stats)

    if args.out_csv:
        analyser.export_csv(args.out_csv)
    if args.out_json:
        analyser.export_json(args.out_json, stats)
    if args.out_pdf:
        analyser.export_pdf(args.out_pdf, stats)


if __name__ == "__main__":
    main()
