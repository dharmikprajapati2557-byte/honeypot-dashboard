"""
Central configuration: ports, and predefined "vulnerable-looking" banners
so nmap/service-detection scans see plausible, older/legit-looking service strings.
You can edit these freely per protocol/profile.
"""

# Each protocol has a dict of selectable banner *profiles*. The active one is chosen
# in config at runtime (persisted to state.json) and can be changed from the web GUI.

BANNER_PROFILES = {
    "ftp": {
        "vsftpd_2.3.4": "220 (vsFTPd 2.3.4)",
        "proftpd_1.3.3c": "220 ProFTPD 1.3.3c Server ready.",
        "generic": "220 FTP Server Ready",
    },
    "ssh": {
        "openssh_7.2p2": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
        "openssh_5.3": "SSH-2.0-OpenSSH_5.3",
        "dropbear_2016": "SSH-2.0-dropbear_2016.74",
    },
    "telnet": {
        "busybox": "BusyBox on embedded-device login:",
        "cisco_ios": "User Access Verification\r\nPassword:",
        "generic": "login: ",
    },
    "smb": {
        # SMB banner realism is handled at the protocol negotiation level (see smb.py);
        # this is the advertised server "comment"/OS string used in negotiation replies.
        "win_srv_2008": "Windows Server 2008 R2 Standard 7601 Service Pack 1",
        "samba_3.6": "Samba 3.6.3",
    },
    "snmp": {
        "cisco_default": "Cisco IOS Software",
        "generic_public": "generic SNMPv1 public community",
    },
    "http": {
        "apache_2.2.8": "Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5",
        "iis_6.0": "Microsoft-IIS/6.0",
        "nginx_1.4.6": "nginx/1.4.6 (Ubuntu)",
    },
}

DEFAULT_PORTS = {
    "http": 8080,     # bind >1024 by default on Windows to avoid admin requirement; can raise to 80 if run elevated
    "ftp": 2121,
    "ssh": 2222,
    "telnet": 2323,
    "smb": 4450,       # real SMB (445) needs elevation + the OS SMB service disabled; see README
    "snmp_udp": 1610,  # real SNMP (161) needs elevation on Windows
}

DEFAULT_BANNER_SELECTION = {
    "ftp": "vsftpd_2.3.4",
    "ssh": "openssh_5.3",
    "telnet": "busybox",
    "smb": "win_srv_2008",
    "snmp": "cisco_default",
    "http": "apache_2.2.8",
}
