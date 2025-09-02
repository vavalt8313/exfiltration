import requests

ONION_ADDRESS = "nmkj3keyfxp6mwve3as6pgpsjsh3scdthxefyxf37qvfunkjwmmhfoad.onion"
proxies = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

def send_file(path):
    url = f"http://{ONION_ADDRESS}/upload"
    with open(path, "rb") as f:
        files = {"file": (path, f)}
        resp = requests.post(url, files=files, proxies=proxies, timeout=60)
    return resp.json()

if __name__ == "__main__":
    result = send_file("testfile.txt")
    print("Result:", result)
