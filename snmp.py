"""
Minimal SNMP v1/v2c honeypot over UDP. Responds to GET requests for sysDescr
with a fake but plausible device string, and logs the community string used
(this is effectively the "credential" in SNMP v1/v2c).
Implements just enough BER/ASN.1 parsing to pull the community string out of
a GetRequest PDU; does not fully implement SNMP semantics.
"""
import socket
import threading
from core import db


def _parse_community(data: bytes):
    # SNMP message: SEQUENCE { version INTEGER, community OCTET STRING, pdu ... }
    try:
        idx = 0
        if data[idx] != 0x30:
            return None
        idx += 1
        # length (skip, handle short form only for simplicity)
        length = data[idx]
        idx += 1
        if length & 0x80:
            nbytes = length & 0x7F
            idx += nbytes
        # version INTEGER
        if data[idx] != 0x02:
            return None
        idx += 1
        vlen = data[idx]
        idx += 1 + vlen
        # community OCTET STRING
        if data[idx] != 0x04:
            return None
        idx += 1
        clen = data[idx]
        idx += 1
        community = data[idx: idx + clen].decode(errors="ignore")
        return community
    except (IndexError, UnicodeDecodeError):
        return None


class SNMPHoneypot:
    name = "snmp"

    def __init__(self, host, port, banner_text=""):
        self.host = host
        self.port = port
        self.banner_text = banner_text
        self._sock = None
        self._thread = None
        self._running = threading.Event()

    def is_running(self):
        return self._running.is_set()

    def start(self):
        if self.is_running():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._running.clear()
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def _serve(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.host, self.port))
            db.log_event(self.name, self.host, self.port, "listener_start", f"bound {self.host}:{self.port}")
        except OSError as e:
            db.log_event(self.name, self.host, self.port, "error", f"bind failed: {e}")
            self._running.clear()
            return

        self._sock.settimeout(1.0)
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            ip, port = addr
            db.log_event(self.name, ip, port, "connect", "")
            community = _parse_community(data)
            if community:
                db.log_auth(self.name, ip, "community_string", community)
            db.log_event(self.name, ip, port, "disconnect", "")
        db.log_event(self.name, self.host, self.port, "listener_stop", "")
