from flask import Flask, send_from_directory, request, jsonify
import os
import base64

app = Flask(__name__)

# Chemin vers le dossier contenant vos fichiers HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.txt')
SUBDOMAINS_FILE = os.path.join(BASE_DIR, 'subdomains_collected.txt')

def collect_subdomains():
    """Collecte tous les sous-domaines depuis le fichier en préservant la casse"""
    try:
        with open(SUBDOMAINS_FILE, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def decode_collected_subdomains():
    """Décode tous les sous-domaines collés comme un seul message en préservant la casse"""
    collected = collect_subdomains()
    if not collected:
        return "Aucun sous-domaine collecté"
    
    try:
        # Ajouter le padding nécessaire
        padding = '=' * (4 - len(collected) % 4)
        decoded = base64.b64decode(collected + padding).decode('utf-8')
        return decoded
    except Exception as e:
        return f"Erreur de décodage: {str(e)} - Contenu: '{collected}'"

@app.before_request
def collect_subdomain():
    """Collecte les sous-domaines en préservant la casse exacte"""
    host = request.host
    parts = host.split('.')
    
    if len(parts) >= 3:
        # Préserver la casse exacte du sous-domaine
        subdomain = parts[0]
        
        # Ajouter le sous-domaine au fichier collé avec la casse exacte
        with open(SUBDOMAINS_FILE, 'a') as f:
            f.write(subdomain)
        
        # Affichage dans le terminal avec la casse
        print("\n" + "="*80)
        print("🎯 COLLECTE DE SOUS-DOMAINE (CASSE PRÉSERVÉE)")
        print(f"Sous-domaine reçu: '{subdomain}'")
        print(f"Longueur: {len(subdomain)} caractères")
        
        # Afficher la chaîne complète collectée
        collected = collect_subdomains()
        print(f"Chaîne complète: '{collected}'")
        
        # Décoder et afficher
        full_message = decode_collected_subdomains()
        print(f"Message décodé: '{full_message}'")
        print("="*80)
        
        # Sauvegarder le message décodé avec la casse
        with open(SECRETS_FILE, 'w', encoding='utf-8') as f:
            f.write(f"Sous-domaines collectés (avec casse): {collected}\n")
            f.write(f"Message décodé: {full_message}\n")
            f.write(f"Longueur: {len(collected)}\n")

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
    """Récupère le message complet décodé avec la casse préservée"""
    message = decode_collected_subdomains()
    collected = collect_subdomains()
    
    return jsonify({
        "collected_subdomains": collected,
        "decoded_message": message,
        "length": len(collected)
    })

@app.route('/api/debug', methods=['GET'])
def debug_subdomains():
    """Debug pour voir exactement ce qui est collecté"""
    collected = collect_subdomains()
    return jsonify({
        "raw_subdomains": collected,
        "hex_representation": collected.encode('utf-8').hex(),
        "length": len(collected),
        "characters": list(collected)
    })

if __name__ == '__main__':
    # Réinitialiser les fichiers au démarrage
    try:
        os.remove(SUBDOMAINS_FILE)
        os.remove(SECRETS_FILE)
    except FileNotFoundError:
        pass
    
    print("\n🕵️ Serveur Flask avec préservation de la casse!")
    print("📍 URL principale: http://localhost:5000")
    print("📍 Test avec casse: http://SmUgc3VpcyB0b24gcGVyZS4gYmxhYmxhYmxh.localhost:5000")
    print("📍 Fichiers créés: subdomains_collected.txt et secrets.txt")
    print("📝 La casse est maintenant préservée pour le décodage base64\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
