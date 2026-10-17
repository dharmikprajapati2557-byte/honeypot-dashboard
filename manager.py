from core import state as state_mod
from core.config import BANNER_PROFILES, DEFAULT_PORTS
from protocols.ftp import FTPHoneypot
from protocols.ssh import SSHHoneypot
from protocols.telnet import TelnetHoneypot
from protocols.snmp import SNMPHoneypot
from protocols.smb import SMBHoneypot
from protocols.http import HTTPHoneypot

BIND_HOST = "0.0.0.0"

CLASSES = {
    "ftp": (FTPHoneypot, DEFAULT_PORTS["ftp"]),
    "ssh": (SSHHoneypot, DEFAULT_PORTS["ssh"]),
    "telnet": (TelnetHoneypot, DEFAULT_PORTS["telnet"]),
    "smb": (SMBHoneypot, DEFAULT_PORTS["smb"]),
    "http": (HTTPHoneypot, DEFAULT_PORTS["http"]),
}

_instances = {}


def _banner_for(proto, key):
    return BANNER_PROFILES[proto].get(key, list(BANNER_PROFILES[proto].values())[0])


def get_instance(proto):
    return _instances.get(proto)


def start_protocol(proto):
    st = state_mod.get_state()
    banner_key = st["protocols"][proto]["banner"]
    if proto == "snmp":
        inst = _instances.get("snmp") or SNMPHoneypot(BIND_HOST, DEFAULT_PORTS["snmp_udp"], _banner_for("snmp", banner_key))
    else:
        cls, port = CLASSES[proto]
        inst = _instances.get(proto) or cls(BIND_HOST, port, _banner_for(proto, banner_key))
    _instances[proto] = inst
    inst.start()
    state_mod.set_protocol_enabled(proto, True)


def stop_protocol(proto):
    inst = _instances.get(proto)
    if inst:
        inst.stop()
    state_mod.set_protocol_enabled(proto, False)


def set_banner(proto, banner_key):
    state_mod.set_protocol_banner(proto, banner_key)
    # if running, restart with new banner
    inst = _instances.get(proto)
    if inst and inst.is_running():
        stop_protocol(proto)
        start_protocol(proto)


def status_snapshot():
    st = state_mod.get_state()
    out = {}
    for proto, cfg in st["protocols"].items():
        inst = _instances.get(proto)
        port = DEFAULT_PORTS.get(proto if proto != "snmp" else "snmp_udp")
        out[proto] = {
            "enabled_config": cfg["enabled"],
            "running": bool(inst and inst.is_running()),
            "banner_key": cfg["banner"],
            "banner_text": _banner_for(proto, cfg["banner"]),
            "port": port,
        }
    return out


def restore_from_state():
    """Call at startup: re-start any protocol that was marked enabled last run."""
    st = state_mod.get_state()
    for proto, cfg in st["protocols"].items():
        if cfg["enabled"]:
            start_protocol(proto)
