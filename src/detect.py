"""
detect.py

Ties everything together: for every finished traffic window,
run both models, log the window, and log + alert on anything
either model flags.

Usage:
    sudo python src/detect.py --iface eth0 --window 5

Requires that src/models/train_models.py has already been run, so
rf_model.pkl, iso_model.pkl and label_encoder.pkl exist.
"""

import argparse
import sys
from pathlib import Path

# Ensure src directory is in Python path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import joblib

import database
from capture import WindowedCapture
from feature_extraction import features_to_vector

MODELS_DIR = Path(__file__).resolve().parent / "models"
CONFIDENCE_THRESHOLD = 0.6          # RF probability threshold to raise an alert


class DetectionEngine:
    def __init__(self):
        self.rf = joblib.load(MODELS_DIR / "rf_model.pkl")
        self.iso = joblib.load(MODELS_DIR / "iso_model.pkl")
        self.encoder = joblib.load(MODELS_DIR / "label_encoder.pkl")
        database.init_db()

    def process_window(self, features, packets):
        database.log_window(features)

        pkt_count = features.get("packet_count", 0)
        if pkt_count == 0:
            return  # empty window, nothing to score

        vector = features_to_vector(features)

        # --- Random Forest: known attack categories ---
        probs = self.rf.predict_proba(vector)[0]
        pred_idx = probs.argmax()
        pred_label = self.encoder.classes_[pred_idx]
        confidence = float(probs[pred_idx])

        if pred_label != "normal" and confidence >= CONFIDENCE_THRESHOLD:
            print(f"[ALERT][random_forest] {pred_label.upper()} detected! (confidence={confidence:.2f}, {pkt_count} packets)")
            database.log_incident("random_forest", pred_label, confidence, features)
        else:
            print(f"[window] analyzed {pkt_count} packets -> {pred_label} (confidence={confidence:.2f})")

        # --- Isolation Forest: catches abnormal behavior using dynamic adaptive threshold ---
        anomaly_score = float(self.iso.decision_function(vector)[0])
        iso_threshold = database.get_iso_threshold()
        is_anomaly = anomaly_score < iso_threshold

        if is_anomaly and pred_label == "normal":
            print(f"[ALERT][isolation_forest] ANOMALY detected! (score={anomaly_score:.3f} < threshold={iso_threshold:.3f}, {pkt_count} packets)")
            database.log_incident(
                "isolation_forest", "anomaly", anomaly_score, features
            )

    def run(self, iface, window_seconds):
        capture = WindowedCapture(iface, window_seconds, self.process_window)
        capture.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time IDS detection loop")
    parser.add_argument("--iface", default=None, help="Network interface (e.g. Wi-Fi). Defaults to active interface.")
    parser.add_argument("--window", type=float, default=5.0, help="Window size in seconds")
    args = parser.parse_args()

    engine = DetectionEngine()
    engine.run(args.iface, args.window)
