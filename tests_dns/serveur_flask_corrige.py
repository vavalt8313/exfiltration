from flask import Flask, send_from_directory, request, jsonify
import os

app = Flask(__name__)

# Chemin vers le dossier contenant vos fichiers HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def serve_index():
    """Sert le fichier site_corrige.html"""
    return send_from_directory(BASE_DIR, 'site_corrige.html')

@app.route('/<path:filename>')
def serve_file(filename):
    """Sert n'importe quel fichier du dossier"""
    return send_from_directory(BASE_DIR, filename)

@app.route('/api/test', methods=['GET'])
def test_connection():
    """Endpoint pour tester la connexion"""
    return jsonify({"message": "Serveur Flask fonctionne correctement!"})

@app.route('/api/data', methods=['POST'])
def receive_data():
    """Endpoint pour recevoir des données"""
    data = request.get_json()
    print(f"Données reçues: {data}")
    return jsonify({"status": "success", "received": data})

if __name__ == '__main__':
    print("Serveur Flask démarré sur http://localhost:5000")
    print("Fichiers disponibles:")
    print("  - http://localhost:5000/ (site_corrige.html)")
    print("  - http://localhost:5000/site.html")
    print("  - http://localhost:5000/site_corrige.html")
    app.run(host='localhost', port=5000, debug=True)
