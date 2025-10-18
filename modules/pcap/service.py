"""
PCAP analysis module.

Provides a FastAPI router that accepts uploaded PCAP/PCAPNG files, performs
lightweight analytics with Scapy, and returns structured JSON results.
"""
from __future__ import annotations

import os
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, UploadFile

try:  # pragma: no cover - optional dependency
    from scapy.all import rdpcap  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.l2 import ARP  # type: ignore
    from scapy.plist import PacketList  # type: ignore

    SCAPY_AVAILABLE = True
    PacketContainer = PacketList
except ImportError as exc:  # pragma: no cover
    rdpcap = None  # type: ignore
    DNS = ICMP = IP = TCP = UDP = ARP = PacketContainer = None  # type: ignore
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = exc


router = APIRouter(prefix="/pcap", tags=["pcap"])


@router.get("/health")
def health() -> Dict[str, Any]:
    """Basic readiness probe for the PCAP module."""
    return {
        "ok": True,
        "module": "pcap",
        "analyze_endpoint": "/pcap/analyze",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Accept a PCAP/PCAPNG upload, parse it with Scapy, and return summary stats.
    """
    if not SCAPY_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis unavailable: Scapy is not installed. "
            "Install scapy in the virtual environment to enable this module.",
        )

    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a .pcap or .pcapng file.",
        )

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            chunk_size = 8192
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                tmp_file.write(chunk)
            tmp_path = tmp_file.name

        packets = rdpcap(tmp_path)
        analysis = analyze_packets(packets)
        analysis["file"] = {
            "name": file.filename,
            "size_bytes": analysis["basic_stats"]["total_bytes"],
        }
        analysis["detections"] = {
            "syn_flood": detect_syn_flood(packets),
        }
        return analysis
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error analyzing file: {exc}") from exc
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


def detect_syn_flood(packets: "PacketContainer") -> List[Dict[str, Any]]:
    """
    Very simple heuristic to highlight sources that send many SYN packets without ACKs.
    Returns a list of suspicious IP summaries.
    """
    syn_packets: defaultdict[str, List[Dict[str, Any]]] = defaultdict(list)
    syn_ack_counts: defaultdict[str, int] = defaultdict(int)

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            flags = packet[TCP].flags
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                src_ip = packet[IP].src
                syn_packets[src_ip].append(
                    {
                        "dst_ip": packet[IP].dst,
                        "dst_port": int(packet[TCP].dport),
                        "time": float(packet.time),
                    }
                )
            elif flags == 0x12:  # SYN-ACK
                dst_ip = packet[IP].dst
                syn_ack_counts[dst_ip] += 1

    alerts: List[Dict[str, Any]] = []
    for src_ip, entries in syn_packets.items():
        syn_count = len(entries)
        syn_ack_count = syn_ack_counts.get(src_ip, 0)

        if syn_count == 0:
            continue

        ratio = syn_ack_count / syn_count if syn_count else 0.0
        if syn_count >= 10 and ratio < 0.2:
            unique_targets = {f"{e['dst_ip']}:{e['dst_port']}" for e in entries}
            alerts.append(
                {
                    "source_ip": src_ip,
                    "syn_count": syn_count,
                    "syn_ack_count": syn_ack_count,
                    "ack_ratio": round(ratio, 2),
                    "unique_targets": len(unique_targets),
                    "severity": "high" if syn_count > 50 else "medium",
                }
            )
    return alerts


def analyze_packets(packets: "PacketContainer") -> Dict[str, Any]:
    """Compute aggregate statistics for a packet capture."""
    total_packets = len(packets)
    if total_packets == 0:
        return {
            "basic_stats": {
                "total_packets": 0,
                "duration": 0.0,
                "unique_ips": 0,
                "total_bytes": 0,
            },
            "protocol_stats": {},
            "top_talkers": [],
            "packet_details": [],
        }

    start_time = float(packets[0].time)
    end_time = float(packets[-1].time)
    duration = round(end_time - start_time, 2)

    protocol_counter: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    dest_counts: Counter[str] = Counter()
    total_bytes = 0

    for packet in packets:
        total_bytes += len(packet)

        if packet.haslayer(TCP):
            protocol_counter["TCP"] += 1
        elif packet.haslayer(UDP):
            protocol_counter["UDP"] += 1
        elif packet.haslayer(ICMP):
            protocol_counter["ICMP"] += 1
        elif packet.haslayer(ARP):
            protocol_counter["ARP"] += 1
        elif packet.haslayer(DNS):
            protocol_counter["DNS"] += 1
        else:
            protocol_counter["Other"] += 1

        if packet.haslayer(IP):
            source_counts[packet[IP].src] += 1
            dest_counts[packet[IP].dst] += 1

    all_ips = set(source_counts) | set(dest_counts)
    top_talkers = [
        [ip, count]
        for ip, count in source_counts.most_common(5)
    ]

    packet_details: List[Dict[str, Any]] = []
    for packet in packets[:10]:
        rel_time = round(float(packet.time) - start_time, 3)
        packet_details.append(
            {
                "relative_time": rel_time,
                "time": rel_time,
                "source": packet[IP].src if packet.haslayer(IP) else "N/A",
                "destination": packet[IP].dst if packet.haslayer(IP) else "N/A",
                "protocol": get_protocol_name(packet),
                "size_bytes": len(packet),
                "size": len(packet),
            }
        )

    return {
        "basic_stats": {
            "total_packets": total_packets,
            "duration": duration,
            "unique_ips": len(all_ips),
            "total_bytes": total_bytes,
        },
        "protocol_stats": dict(protocol_counter),
        "top_talkers": top_talkers,
        "packet_details": packet_details,
    }


def get_protocol_name(packet) -> str:
    """Identify a packet's protocol or high-level application."""
    if packet.haslayer(TCP):
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
        if 80 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport):
            return "HTTPS"
        if 22 in (sport, dport):
            return "SSH"
        return "TCP"
    if packet.haslayer(UDP):
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
        if 53 in (sport, dport):
            return "DNS"
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    return "Other"
