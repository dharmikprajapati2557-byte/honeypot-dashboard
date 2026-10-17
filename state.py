import json
import os
import threading
from werkzeug.security import generate_password_hash

STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "state.json")
_lock = threading.Lock()

_DEFAULT = {
    "auth_configured": False,
    "username": None,
    "password_hash": None,
    "protocols": {
        "http": {"enabled": False, "banner": "apache_2.2.8"},
        "ftp": {"enabled": False, "banner": "vsftpd_2.3.4"},
        "ssh": {"enabled": False, "banner": "openssh_5.3"},
        "snmp": {"enabled": False, "banner": "cisco_default"},
        "smb": {"enabled": False, "banner": "win_srv_2008"},
        "telnet": {"enabled": False, "banner": "busybox"},
    },
}


def _load():
    if not os.path.exists(STATE_PATH):
        return json.loads(json.dumps(_DEFAULT))
    with open(STATE_PATH, "r") as f:
        return json.load(f)


def _save(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def get_state():
    with _lock:
        return _load()


def set_auth(username, password):
    with _lock:
        state = _load()
        state["auth_configured"] = True
        state["username"] = username
        state["password_hash"] = generate_password_hash(password)
        _save(state)


def is_auth_configured():
    return _load().get("auth_configured", False)


def set_protocol_enabled(name, enabled):
    with _lock:
        state = _load()
        state["protocols"][name]["enabled"] = enabled
        _save(state)


def set_protocol_banner(name, banner_key):
    with _lock:
        state = _load()
        state["protocols"][name]["banner"] = banner_key
        _save(state)
