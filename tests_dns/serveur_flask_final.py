from flask import Flask, send_from_directory, request, jsonify
import os
import base64

app = Flask(__name__)

# Chemin vers le dossier contenant vos fichiers HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.txt')
SUBDOMAINS_FILE = os.path.join(BASE_DIR, 'subdomains_collected.txt')

def collect_subdomains():
    """Collecte tous les sous-domaines depuis le fichier"""
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def decode_collected_subdomains():
    """Décode tous les sous-domaines collés comme un seul message"""
    collected = collect_subdomains()
    if not collected:
        return "Aucun sous-domaine collecté"
    
    try:
        # Ajouter le padding nécessaire
        padding = '=' * (4 - len(collected) % 4)
        decoded = base64.b64decode(collected + padding).decode('utf-8')
        return decoded
    except Exception as e:
        return f"Erreur de décodage: {str(e)}"

@app.before_request
def collect_subdomain():
    """Collecte les sous-domaines sans les décoder immédiatement"""
    host = request.host
    parts = host.split('.')
    
    if len(parts) >= 3:
        subdomain = parts[0]
        
        # Ajouter le sous-domaine au fichier collé
        with open(SUBDOMAINS_FILE, 'a') as f:
            f.write(subdomain)
        
        # Affichage dans le terminal
        print("\n" + "="*60)
        print("🎯 COLLECTE DE SOUS-DOMAINE")
        print(f"Sous-domaine reçu: {subdomain}")
        
        # Lire le message complet décodé
        full_message = decode_collected_subdomains()
        print(f"Message complet décodé: {full_message}")
        print("="*60)
        
        # Sauvegarder le message décodé
        with open(SECRETS_FILE, 'w') as f:
            f.write(f"Sous-domaines collectés: {collect_subdomains()}\n")
            f.write(f"Message décodé: {full_message}\n")

@app.route('/')
def serve_index():
    """Sert le fichier site_corrige.html"""
    return send_from_directory(BASE_DIR, 'site_corrige.html')

@app.route('/<path:filename>')
def serve_file(filename):
    """Sert n'importe quel fichier du dossier"""
    return send_from_directory(BASE_DIR, filename)

@app.route('/api/reset', methods=['POST'])
def reset_collection():
    """Réinitialise la collection de sous-domaines"""
    try:
        os.remove(SUBDOMAINS_FILE)
        os.remove(SECRETS_FILE)
    except FileNotFoundError:
        pass
    
    return jsonify({"message": "Collection réinitialisée"})

@app.route('/api/message', methods=['GET'])
def get_decoded_message():
    """Récupère le message complet décodé"""
    message = decode_collected_subdomains()
    collected = collect_subdomains()
    
    return jsonify({
        "collected_subdomains": collected,
        "decoded_message": message
    })

if __name__ == '__main__':
    # Réinitialiser les fichiers au démarrage
    try:
        os.remove(SUBDOMAINS_FILE)
        os.remove(SECRETS_FILE)
    except FileNotFoundError:
        pass
    
    print("\n🕵️ Serveur Flask avec collection de messages cachés!")
    print("📍 URL principale: http://localhost:5000")
    print("📍 Collection de sous-domaines: http://cGFyMS.localhost:5000 puis http://dXQ0.localhost:5000")
    print("📍 Fichiers créés: subdomains_collected.txt et secrets.txt")
    print("\n📝 Tous les sous-domaines seront collés et décodés à la fin\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
