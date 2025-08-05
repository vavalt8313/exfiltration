from flask import Flask, send_from_directory, request, jsonify
import os
from urllib.parse import urlparse

app = Flask(__name__)

# Chemin vers le dossier contenant vos fichiers HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def extract_subdomain(host):
    """Extrait le sous-domaine de l'hôte"""
    parts = host.split('.')
    if len(parts) >= 3:
        return parts[0]  # Premier élément est le sous-domaine
    return None

@app.before_request
def log_request_info():
    """Log les informations de la requête incluant les sous-domaines"""
    host = request.host
    subdomain = extract_subdomain(host)
    
    # Affichage coloré dans le terminal
    print("\n" + "="*60)
    print(f"📡 NOUVELLE REQUÊTE")
    print(f"Méthode: {request.method}")
    print(f"URL: {request.url}")
    print(f"Hôte: {host}")
    
    if subdomain:
        print(f"🎯 Sous-domaine détecté: {subdomain}")
    else:
        print(f"🎯 Sous-domaine: Aucun (domaine principal)")
    
    print(f"IP Client: {request.remote_addr}")
    print("="*60)

@app.route('/')
def serve_index():
    """Sert le fichier site_corrige.html"""
    host = request.host
    subdomain = extract_subdomain(host)
    
    if subdomain:
        print(f"✓ Accès via sous-domaine: {subdomain}")
    
    return send_from_directory(BASE_DIR, 'site_corrige.html')

@app.route('/<path:filename>')
def serve_file(filename):
    """Sert n'importe quel fichier du dossier"""
    host = request.host
    subdomain = extract_subdomain(host)
    
    if subdomain:
        print(f"✓ Fichier '{filename}' demandé via sous-domaine: {subdomain}")
    
    return send_from_directory(BASE_DIR, filename)

@app.route('/api/subdomain-test', methods=['GET'])
def test_subdomain():
    """Endpoint pour tester la détection de sous-domaine"""
    host = request.host
    subdomain = extract_subdomain(host)
    
    return jsonify({
        "host": host,
        "subdomain": subdomain,
        "message": f"Sous-domaine détecté: {subdomain}" if subdomain else "Pas de sous-domaine"
    })

@app.route('/api/data', methods=['POST'])
def receive_data():
    """Endpoint pour recevoir des données avec affichage du sous-domaine"""
    host = request.host
    subdomain = extract_subdomain(host)
    
    data = request.get_json()
    
    print(f"✓ Données reçues via sous-domaine: {subdomain or 'principal'}")
    print(f"Données: {data}")
    
    return jsonify({
        "status": "success",
        "received": data,
        "subdomain": subdomain,
        "host": host
    })

if __name__ == '__main__':
    print("\n🚀 Serveur Flask amélioré démarré!")
    print("📍 URL principale: http://localhost:5000")
    print("📍 URL avec sous-domaine: http://test.localhost:5000 (exemple)")
    print("📍 URL avec sous-domaine: http://api.localhost:5000 (exemple)")
    print("\n📝 Les sous-domaines seront affichés dans le terminal pour chaque requête\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
