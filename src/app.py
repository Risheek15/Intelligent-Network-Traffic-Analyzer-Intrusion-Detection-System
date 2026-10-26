"""
app.py

Flask backend that:
  - serves the Traffic Analyzer (/analyzer) and IDS Dashboard (/ids)
  - exposes JSON endpoints the dashboards poll for live data
  - authenticates technicians and adapts detection thresholds
"""

import sys
from pathlib import Path
from flask import Flask, jsonify, render_template, request, session, redirect, url_for

# Ensure src directory is in Python path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import database

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = "fresh-session-key-ids-" + str(Path(__file__).stat().st_mtime)


@app.before_request
def require_authentication():
    allowed = ["login", "register", "static"]
    if request.endpoint and request.endpoint not in allowed:
        if "user" not in session:
            return redirect(url_for("login"))


@app.route("/")
@app.route("/analyzer")
def analyzer():
    user = session.get("user")
    return render_template("analyzer.html", user=user)


@app.route("/ids")
def ids():
    user = session.get("user")
    return render_template("ids.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = database.authenticate_user(username, password)
        if user:
            session["user"] = user["username"]
            return redirect(url_for("analyzer"))
        else:
            error = "Invalid Technician ID or Password."
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3 or len(password) < 4:
            error = "Username must be at least 3 characters and password at least 4 characters."
        else:
            try:
                database.add_user(username, password)
                success = f"Account '{username}' created! You can now log in."
            except Exception as e:
                error = f"Failed to create account: {e}"
    return render_template("register.html", error=error, success=success)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/api/windows")
def api_windows():
    limit = int(request.args.get("limit", 50))
    return jsonify(database.get_recent_windows(limit))


@app.route("/api/incidents")
def api_incidents():
    limit = int(request.args.get("limit", 500))
    return jsonify(database.get_recent_incidents(limit))


@app.route("/api/incidents/<int:incident_id>/verdict", methods=["POST"])
def api_set_verdict(incident_id):
    if "user" not in session:
        return jsonify({"error": "Technician login required to set verdicts", "require_login": True}), 401
    body = request.get_json(force=True) or {}
    verdict = body.get("verdict")
    if verdict not in ("true_positive", "false_positive"):
        return jsonify({"error": "verdict must be 'true_positive' or 'false_positive'"}), 400
    inc = database.get_incident_by_id(incident_id)
    prev_verdict = inc.get("verdict") if inc else None
    database.set_incident_verdict(incident_id, verdict)

    # Dynamic adaptation: update isolation forest threshold based on technician verdict
    new_threshold = None
    if inc and inc.get("source_model") == "isolation_forest":
        score = inc.get("confidence") or 0.0
        new_threshold = database.adapt_iso_threshold(verdict, score, prev_verdict=prev_verdict)

    return jsonify({"status": "ok", "new_threshold": new_threshold})


@app.route("/api/incidents/clear", methods=["POST"])
def api_clear_incidents():
    if "user" not in session:
        return jsonify({"error": "Technician login required to clear incidents", "require_login": True}), 401
    database.clear_incidents()
    return jsonify({"status": "ok"})


@app.route("/api/traffic/clear", methods=["POST"])
def api_clear_traffic():
    if "user" not in session:
        return jsonify({"error": "Technician login required to reset traffic graph", "require_login": True}), 401
    database.clear_windows()
    return jsonify({"status": "ok"})


@app.route("/api/summary")
def api_summary():
    windows = database.get_recent_windows(200)
    incidents = database.get_recent_incidents(500)

    total_packets = sum((w.get("packet_count") or 0) for w in windows)
    total_bytes = sum((w.get("byte_count") or 0) for w in windows)
    count = len(windows) if windows else 1
    avg_tcp = sum((w.get("tcp_ratio") or 0) for w in windows) / count
    avg_udp = sum((w.get("udp_ratio") or 0) for w in windows) / count
    avg_icmp = sum((w.get("icmp_ratio") or 0) for w in windows) / count

    return jsonify({
        "windows_seen": len(windows),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_mix": {"tcp": round(avg_tcp, 3), "udp": round(avg_udp, 3), "icmp": round(avg_icmp, 3)},
        "incident_count": len(incidents),
        "iso_threshold": database.get_iso_threshold(),
    })


if __name__ == "__main__":
    database.init_db()
    app.run(debug=True, port=5000)
