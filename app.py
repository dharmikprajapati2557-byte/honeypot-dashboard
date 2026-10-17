import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash

from core import db, state as state_mod, manager
from core.config import BANNER_PROFILES

app = Flask(__name__)
app.secret_key = os.urandom(32)

db.init_db()
manager.restore_from_state()


def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authed"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if state_mod.is_auth_configured():
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(password) < 6:
            return render_template("setup.html", error="Username required, password min 6 chars.")
        state_mod.set_auth(username, password)
        return redirect(url_for("login"))
    return render_template("setup.html", error=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not state_mod.is_auth_configured():
        return redirect(url_for("setup"))
    if request.method == "POST":
        st = state_mod.get_state()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == st["username"] and check_password_hash(st["password_hash"], password):
            session["authed"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"), banner_profiles=BANNER_PROFILES)


# ---------- API ----------

@app.route("/api/status")
@login_required
def api_status():
    return jsonify(manager.status_snapshot())


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/events")
@login_required
def api_events():
    proto = request.args.get("protocol", "all")
    limit = int(request.args.get("limit", 100))
    return jsonify(db.get_recent_events(limit=limit, protocol=proto))


@app.route("/api/auth-attempts")
@login_required
def api_auth_attempts():
    limit = int(request.args.get("limit", 100))
    return jsonify(db.get_recent_auth(limit=limit))


@app.route("/api/protocol/<proto>/start", methods=["POST"])
@login_required
def api_start(proto):
    manager.start_protocol(proto)
    return jsonify({"ok": True})


@app.route("/api/protocol/<proto>/stop", methods=["POST"])
@login_required
def api_stop(proto):
    manager.stop_protocol(proto)
    return jsonify({"ok": True})


@app.route("/api/protocol/<proto>/banner", methods=["POST"])
@login_required
def api_banner(proto):
    key = request.json.get("banner_key")
    manager.set_banner(proto, key)
    return jsonify({"ok": True})


@app.route("/api/export")
@login_required
def api_export():
    data = db.export_logs_json()
    resp = app.response_class(
        response=json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=honeypot_logs.json"},
    )
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
