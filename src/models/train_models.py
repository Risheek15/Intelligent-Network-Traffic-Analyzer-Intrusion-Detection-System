"""
train_models.py

Trains the two models the system uses at inference time:

1. Random Forest  -> supervised classifier over labelled flow windows.
   Recognizes known categories: normal / port_scan / dos / brute_force.

2. Isolation Forest -> unsupervised anomaly detector, trained ONLY on
   rows labelled "normal", so it learns what normal looks like and
   flags anything that deviates from it -- including attack types it
   never saw a label for.

Usage:
    python src/models/train_models.py --data data/sample_traffic.csv

Outputs (saved next to this script):
    rf_model.pkl
    iso_model.pkl
    label_encoder.pkl
    evaluation_report.txt   (confusion matrix + precision/recall)
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

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

OUT_DIR = Path(__file__).resolve().parent


def train(data_path):
    df = pd.read_csv(data_path)
    missing = set(FEATURE_COLUMNS + ["label"]) - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    X = df[FEATURE_COLUMNS]
    y_raw = df["label"]

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Random Forest (supervised) ---
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)

    report = classification_report(
        y_test, y_pred, target_names=encoder.classes_, digits=3
    )
    cm = confusion_matrix(y_test, y_pred)

    print("=== Random Forest evaluation ===")
    print(report)
    print("Confusion matrix (rows=true, cols=predicted):")
    print(cm)

    with open(OUT_DIR / "evaluation_report.txt", "w") as f:
        f.write("Random Forest classification report\n")
        f.write("=====================================\n")
        f.write(report)
        f.write("\nConfusion matrix (rows=true, cols=predicted)\n")
        f.write(f"labels: {list(encoder.classes_)}\n")
        f.write(str(cm))

    # --- Isolation Forest (unsupervised, trained on normal traffic only) ---
    normal_mask = y_raw == "normal"
    iso = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42
    )
    iso.fit(X[normal_mask])

    joblib.dump(rf, OUT_DIR / "rf_model.pkl")
    joblib.dump(iso, OUT_DIR / "iso_model.pkl")
    joblib.dump(encoder, OUT_DIR / "label_encoder.pkl")

    print(f"\nSaved rf_model.pkl, iso_model.pkl, label_encoder.pkl to {OUT_DIR}")
    print(f"Full evaluation report written to {OUT_DIR / 'evaluation_report.txt'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train RF + IsolationForest models")
    parser.add_argument(
        "--data", type=str, default="data/sample_traffic.csv",
        help="Path to labelled CSV with FEATURE_COLUMNS + a 'label' column"
    )
    args = parser.parse_args()
    train(args.data)
