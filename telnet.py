from protocols.base import BaseHoneypot
from core import db


class TelnetHoneypot(BaseHoneypot):
    name = "telnet"

    def handle(self, conn, addr):
        ip = addr[0]
        conn.sendall((self.banner_text + "\r\n").encode())
        if "login" not in self.banner_text.lower():
            conn.sendall(b"login: ")
        username = self._readline(conn)
        db.log_event(self.name, ip, addr[1], "command", f"login={username}")
        conn.sendall(b"Password: ")
        password = self._readline(conn)
        db.log_auth(self.name, ip, username, password)
        conn.sendall(b"\r\nLogin incorrect\r\n")

    def _readline(self, conn, maxlen=256):
        buf = b""
        while len(buf) < maxlen:
            chunk = conn.recv(1)
            if not chunk or chunk in (b"\n", b"\r"):
                break
            buf += chunk
        return buf.decode(errors="ignore").strip()
