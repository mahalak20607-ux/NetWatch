
from collections import deque
from threading import Lock, Thread
from datetime import datetime
import time

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS

_packets = deque(maxlen=5000)
_lock = Lock()
_started = False
_error = None
_last_time = None


def packet_callback(packet):
    global _last_time

    try:
        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        elif IPv6 in packet:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        else:
            return

        if DNS in packet:
            protocol = "DNS"
        elif TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        port = 0
        if TCP in packet:
            port = int(packet[TCP].dport)
        elif UDP in packet:
            port = int(packet[UDP].dport)

        now = time.time()

        with _lock:
            interval = 0 if _last_time is None else min(
                now - _last_time, 60
            )
            _last_time = now

            _packets.append({
                "timestamp": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "source_ip": src,
                "destination_ip": dst,
                "protocol": protocol,
                "packet_size": len(packet),
                "destination_port": port,
                "interarrival_seconds": interval,
            })

    except Exception:
        pass


def _capture(interface):
    global _error

    try:
        sniff(
            iface=interface or None,
            prn=packet_callback,
            store=False,
        )
    except Exception as exc:
        _error = str(exc)


def start_monitor(interface=None):
    global _started

    if _started:
        return

    _started = True
    Thread(
        target=_capture,
        args=(interface,),
        daemon=True,
    ).start()


def get_packets():
    with _lock:
        return list(_packets)


def get_error():
    return _error
