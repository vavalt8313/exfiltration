from flask import Flask, send_from_directory, request, jsonify
import logging
import json
import os

app = Flask(__name__)

# Configuration du logger
logging.basicConfig(level=logging.INFO)

# Configuration
UPLOAD_DIR = 'uploads'
CHUNK_FILE = os.path.join(UPLOAD_DIR, 'received_chunks.json')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def try_opening_file():
    try:
        with open(CHUNK_FILE, 'r') as f:
            json_data = json.load(f)
    except:
        json_data = {}
        with open(CHUNK_FILE, 'w') as f:
            json.dump(json_data, f, indent=4)

# Créer le dossier uploads s'il n'existe pas
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.before_request
def log_request_info():
    logging.info(f"[{request.method}] {request.path} from {request.remote_addr}")

@app.route('/<path:filename>')
def serve_file(filename):
    """Sert n'importe quel fichier du dossier"""
    return send_from_directory(BASE_DIR, filename)

@app.route('/post-example', methods=['POST'])
def post_example():

    data = request.get_json()
    ip_client = request.remote_addr

    chunk = data.get("part", "")
    index = data.get("index", 0)

    try_opening_file()
    with open(CHUNK_FILE, 'r') as f:
        json_data = json.load(f)
    
    if (ip_client not in json_data.keys()):
        json_data[ip_client] = []
    
    if (index < 0):
        index = len(json_data[ip_client])
        json_data[ip_client].append(chunk)
    else:
        json_data[ip_client][index] += chunk

    with open(CHUNK_FILE, 'w') as f:
        json.dump(json_data, f, indent=4)
    return jsonify({"index": index})

if __name__ == '__main__':
    try:
        print("Serveur Flask démarré sur http://localhost:5000 (Ctrl+C pour arrêter)")
        app.run(host='0.0.0.0', debug=True, port=8888)
    except KeyboardInterrupt:
        print("\nArrêt manuel détecté. Fermeture du serveur...")
