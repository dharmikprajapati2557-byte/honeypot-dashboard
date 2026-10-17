from protocols.base import BaseHoneypot
from core import db

FAKE_PAGE = b"""<html><head><title>Index of /</title></head>
<body><h1>It works!</h1><p>Apache default page</p></body></html>"""


class HTTPHoneypot(BaseHoneypot):
    name = "http"

    def handle(self, conn, addr):
        ip = addr[0]
        data = conn.recv(8192)
        if not data:
            return
        request_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
        db.log_event(self.name, ip, addr[1], "command", request_line)

        # log headers too (credentials sometimes appear in Authorization: Basic)
        try:
            headers_block = data.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
            for h in headers_block.split("\r\n")[1:]:
                if h.lower().startswith("authorization"):
                    db.log_auth(self.name, ip, "http_auth_header", h.split(":", 1)[1].strip())
        except (IndexError, UnicodeDecodeError):
            pass

        body = FAKE_PAGE
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {self.banner_text}\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + body
        try:
            conn.sendall(response)
        except OSError:
            pass
