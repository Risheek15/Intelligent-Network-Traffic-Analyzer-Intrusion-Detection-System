"""
feature_extraction.py

Converts a buffer of raw packet records into rolling-window,
flow-level statistical features. This is the bridge between the
packet capture module (capture.py) and the ML models.

A "packet record" is a plain dict with the fields pulled off each
frame by capture.py:
    {
        "timestamp": float,
        "src_ip": str,
        "dst_ip": str,
        "src_port": int,
        "dst_port": int,
        "protocol": str,   # "TCP" / "UDP" / "ICMP" / "OTHER"
        "length": int,
    }
"""

import pandas as pd

# Order matters: this is the exact column order the models expect.
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_src_ports",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "packets_per_second",
    "distinct_flows",
    "syn_like_ratio",
]


def _protocol_ratio(protocols, target):
    if not protocols:
        return 0.0
    return protocols.count(target) / len(protocols)


def extract_window_features(packets, window_seconds):
    """
    Turn a list of packet-record dicts (all packets captured in one
    rolling window) into a single feature row.

    Returns a dict keyed by FEATURE_COLUMNS, plus 'window_start' and
    'window_end' for bookkeeping/display purposes.
    """
    if not packets:
        return {col: 0.0 for col in FEATURE_COLUMNS} | {
            "window_start": None,
            "window_end": None,
            "src_ip": "-",
            "dst_ip": "-",
            "dst_port": "-",
            "protocol": "OTHER",
        }

    df = pd.DataFrame(packets)
    protocols = df["protocol"].tolist()

    packet_count = len(df)
    byte_count = int(df["length"].sum())
    avg_packet_size = float(df["length"].mean())

    unique_dst_ips = df["dst_ip"].nunique()
    unique_dst_ports = df["dst_port"].nunique()
    unique_src_ports = df["src_port"].nunique()

    # A "flow" here is approximated as a unique
    # (src_ip, dst_ip, dst_port, protocol) tuple.
    distinct_flows = df.drop_duplicates(
        subset=["src_ip", "dst_ip", "dst_port", "protocol"]
    ).shape[0]

    # Rough proxy for scan-like behaviour: many distinct destination
    # ports touched relative to total packets sent.
    syn_like_ratio = (
        unique_dst_ports / packet_count if packet_count else 0.0
    )

    # Identify primary network endpoints for security incident response
    src_ip = str(df["src_ip"].value_counts().index[0]) if not df["src_ip"].empty else "-"
    dst_ip = str(df["dst_ip"].value_counts().index[0]) if not df["dst_ip"].empty else "-"
    if unique_dst_ports > 15:
        dst_port_str = f"Multi ({unique_dst_ports})"
    elif not df["dst_port"].empty:
        dst_port_str = str(int(df["dst_port"].mode()[0]))
    else:
        dst_port_str = "-"

    primary_protocol = str(df["protocol"].value_counts().index[0]) if not df["protocol"].empty else "TCP"

    features = {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "avg_packet_size": avg_packet_size,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "unique_src_ports": unique_src_ports,
        "tcp_ratio": _protocol_ratio(protocols, "TCP"),
        "udp_ratio": _protocol_ratio(protocols, "UDP"),
        "icmp_ratio": _protocol_ratio(protocols, "ICMP"),
        "packets_per_second": packet_count / window_seconds if window_seconds else 0.0,
        "distinct_flows": distinct_flows,
        "syn_like_ratio": syn_like_ratio,
        "window_start": float(df["timestamp"].min()),
        "window_end": float(df["timestamp"].max()),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port_str,
        "protocol": primary_protocol,
    }
    return features


def features_to_vector(features):
    """
    Order a feature dict into the input the models expect. Returned as a
    single-row DataFrame (not a bare array) so column names match what the
    models were trained on and scikit-learn doesn't warn about it.
    """
    return pd.DataFrame([[features[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
