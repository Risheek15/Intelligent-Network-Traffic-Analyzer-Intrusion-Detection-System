"""
capture.py

Live packet capture using Scapy. Reads raw frames off a network
interface, pulls out the fields the feature-extraction stage needs,
and groups them into fixed-length rolling time windows.

Run directly for a quick sanity check:
    sudo python src/capture.py --iface eth0 --window 5

NOTE: Raw packet capture requires elevated privileges (root / admin)
and a working libpcap install. On most Linux distros:
    sudo apt-get install libpcap-dev
"""

import argparse
import sys
import time
from collections import deque
from pathlib import Path

# Ensure src directory is in Python path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

from feature_extraction import extract_window_features


def packet_to_record(pkt):
    """Extract the fields we care about from a single Scapy packet."""
    if IP not in pkt:
        return None

    proto = "OTHER"
    src_port = 0
    dst_port = 0

    if TCP in pkt:
        proto = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif ICMP in pkt:
        proto = "ICMP"

    return {
        "timestamp": float(pkt.time),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": len(pkt),
    }


class WindowedCapture:
    """
    Wraps scapy.sniff and hands finished windows of packet records to
    a callback as soon as `window_seconds` has elapsed.
    """

    def __init__(self, iface, window_seconds, on_window):
        self.iface = iface or conf.iface
        self.window_seconds = window_seconds
        self.on_window = on_window
        self.buffer = deque()
        self.window_start = time.time()
        self.stopped = False

    def _handle_packet(self, pkt):
        record = packet_to_record(pkt)
        if record is None:
            return
        self.buffer.append(record)

        if time.time() - self.window_start >= self.window_seconds:
            self._flush()

    def _flush(self):
        packets = list(self.buffer)
        self.buffer.clear()
        features = extract_window_features(packets, self.window_seconds)
        self.window_start = time.time()
        self.on_window(features, packets)

    def start(self):
        iface_name = getattr(self.iface, "name", self.iface) or "default"
        print(f"[capture] listening on {iface_name}, "
              f"{self.window_seconds}s windows (Ctrl+C to stop)")
        while not self.stopped:
            try:
                sniff(iface=self.iface, prn=self._handle_packet, store=False, timeout=1)
                if time.time() - self.window_start >= self.window_seconds:
                    self._flush()
            except KeyboardInterrupt:
                print("\n[capture] stopping...")
                break


def _demo_callback(features, packets):
    print(f"[window] {len(packets)} packets -> {features}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live packet capture")
    parser.add_argument("--iface", default=None, help="Network interface (e.g. Wi-Fi, eth0). Defaults to active interface.")
    parser.add_argument("--window", type=float, default=5.0, help="Window size in seconds")
    args = parser.parse_args()

    capture = WindowedCapture(args.iface, args.window, _demo_callback)
    capture.start()
