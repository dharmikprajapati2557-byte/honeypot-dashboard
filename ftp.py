from protocols.base import BaseHoneypot
from core import db


class FTPHoneypot(BaseHoneypot):
    name = "ftp"

    def handle(self, conn, addr):
        ip = addr[0]
        conn.sendall((self.banner_text + "\r\n").encode())
        username = None
        while True:
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode(errors="ignore").strip()
            db.log_event(self.name, ip, addr[1], "command", line)
            upper = line.upper()
            if upper.startswith("USER"):
                username = line[5:].strip()
                conn.sendall(b"331 Please specify the password.\r\n")
            elif upper.startswith("PASS"):
                password = line[5:].strip()
                db.log_auth(self.name, ip, username, password)
                conn.sendall(b"530 Login incorrect.\r\n")
            elif upper.startswith("SYST"):
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif upper.startswith("FEAT"):
                conn.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"502 Command not implemented.\r\n")
