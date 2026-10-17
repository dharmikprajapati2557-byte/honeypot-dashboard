"""
Lightweight SMB honeypot. Full SMB/SMB2 implementation is a large protocol;
this listener accepts the TCP connection on the SMB port, reads the client's
negotiate request, and logs it (dialects offered reveal the scanning tool /
client OS). It does not complete a real SMB session -- for a fully interactive
SMB honeypot, deploy Cowrie/Conpot-style dedicated tooling instead. This
module still causes nmap to correctly identify an open microsoft-ds/SMB port.
"""
from protocols.base import BaseHoneypot
from core import db


class SMBHoneypot(BaseHoneypot):
    name = "smb"

    def handle(self, conn, addr):
        ip = addr[0]
        data = conn.recv(4096)
        if data:
            db.log_event(self.name, ip, addr[1], "command", f"negotiate_request({len(data)}B): {data[:64].hex()}")
        # Minimal SMB1 negotiate response header so nmap's service probe sees a
        # coherent SMB reply rather than a reset. Real dialect nego is skipped.
        # NetBIOS Session Service header + SMB header (structure only, not a full impl).
        smb_header = bytes.fromhex(
            "ff534d4b" +  # \xffSMB
            "72" +        # command: negotiate
            "00000000" +  # status
            "98" +        # flags
            "0000" +      # flags2 (partial)
            "0000" +
            "0000000000000000" +
            "0000" +
            "0000" + "0000" + "0000" + "0000"
        )
        netbios_header = bytes([0x00]) + len(smb_header).to_bytes(3, "big")
        try:
            conn.sendall(netbios_header + smb_header)
        except OSError:
            pass
