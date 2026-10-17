import socket
import threading
from core import db


class BaseHoneypot:
    name = "base"

    def __init__(self, host, port, banner_text=""):
        self.host = host
        self.port = port
        self.banner_text = banner_text
        self._sock = None
        self._thread = None
        self._running = threading.Event()

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

    def is_running(self):
        return self._running.is_set()

    def _serve(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.listen(50)
            db.log_event(self.name, self.host, self.port, "listener_start", f"bound {self.host}:{self.port}")
        except OSError as e:
            db.log_event(self.name, self.host, self.port, "error", f"bind failed: {e}")
            self._running.clear()
            return

        while self._running.is_set():
            try:
                self._sock.settimeout(1.0)
                try:
                    conn, addr = self._sock.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._safe_handle, args=(conn, addr), daemon=True).start()
            except OSError:
                break
        db.log_event(self.name, self.host, self.port, "listener_stop", "")

    def _safe_handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        db.log_event(self.name, ip, port, "connect", "")
        try:
            conn.settimeout(30)
            self.handle(conn, addr)
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
        except Exception as e:
            db.log_event(self.name, ip, port, "error", str(e))
        finally:
            db.log_event(self.name, ip, port, "disconnect", "")
            try:
                conn.close()
            except OSError:
                pass

    def handle(self, conn, addr):
        raise NotImplementedError
