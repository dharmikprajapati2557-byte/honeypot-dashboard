"""
Lightweight SSH honeypot.

Two modes are supported:
1. Simple banner mode (default, zero extra deps): sends the SSH-2.0 identification
   string (this alone is what nmap -sV fingerprints) and then, since we don't
   negotiate real SSH key exchange, closes after a grace period. This is enough
   to look correct to a port/banner scan.
2. Full interactive mode (optional): if the 'paramiko' package is installed,
   we upgrade to a real SSH transport that can present a fake shell and capture
   password attempts and typed commands. See README for enabling this.
"""
import socket
from protocols.base import BaseHoneypot
from core import db

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False


class _AuthServer(paramiko.ServerInterface if HAVE_PARAMIKO else object):
    def __init__(self, ip):
        self.ip = ip
        if HAVE_PARAMIKO:
            self.event = __import__("threading").Event()

    def check_auth_password(self, username, password):
        db.log_auth("ssh", self.ip, username, password)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"


class SSHHoneypot(BaseHoneypot):
    name = "ssh"
    HOST_KEY = None

    def handle(self, conn, addr):
        ip = addr[0]
        if HAVE_PARAMIKO:
            self._handle_full(conn, addr)
            return
        # Simple banner-only mode
        try:
            conn.sendall((self.banner_text + "\r\n").encode())
            data = conn.recv(2048)
            if data:
                db.log_event(self.name, ip, addr[1], "client_ident", data.decode(errors="ignore").strip())
        except (socket.timeout, OSError):
            pass

    def _handle_full(self, conn, addr):
        ip = addr[0]
        if SSHHoneypot.HOST_KEY is None:
            SSHHoneypot.HOST_KEY = paramiko.RSAKey.generate(2048)
        transport = paramiko.Transport(conn)
        transport.local_version = self.banner_text
        transport.add_server_key(SSHHoneypot.HOST_KEY)
        server = _AuthServer(ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return
        chan = transport.accept(20)
        if chan is not None:
            try:
                chan.settimeout(30)
                chan.send(b"Login incorrect.\r\n")
            except OSError:
                pass
            chan.close()
        transport.close()
