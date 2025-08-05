from flask import Flask, send_from_directory, request, jsonify
import os
import base64

app = Flask(__name__)

# Chemin vers le dossier contenant vos fichiers HTML
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.txt')

def decode_subdomain_message(subdomain):
    """Décode le sous-domaine en base64 et retourne le message caché"""
    try:
        # Ajouter le padding nécessaire pour base64
        padding = '=' * (4 - len(subdomain) % 4)
        decoded = base64.b64decode(subdomain + padding).decode('utf-8')
        return decoded
    except:
        return f"Message non décodable: {subdomain}"

def save_secret_message(subdomain, decoded_message):
    """Enregistre le sous-domaine et le message décodé dans un fichier"""
    with open(SECRETS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"Sous-domaine: {subdomain}\n")
        f.write(f"Message décodé: {decoded_message}\n")
        f.write("-" * 50 + "\n")

@app.before_request
def log_and_save_subdomain():
    """Log et enregistre les sous-domaines avec messages cachés"""
    host = request.host
    parts = host.split('.')
    
    if len(parts) >= 3:
        subdomain = parts[0]
        decoded = decode_subdomain_message(subdomain)
        
        # Affichage dans le terminal
        print("\n" + "="*60)
        print("🔍 DÉTECTION DE MESSAGE CACHÉ")
        print(f"Sous-domaine: {subdomain}")
        print(f"Message décodé: {decoded}")
        print("="*60)
        
        # Enregistrement dans le fichier
        save_secret_message(subdomain, decoded)

@app.route('/')
def serve_index():
    """Sert le fichier site_corrige.html"""
    return send_from_directory(BASE_DIR, 'site_corrige.html')

@app.route('/<path:filename>')
def serve_file(filename):
    """Sert n'importe quel fichier du dossier"""
    return send_from_directory(BASE_DIR, filename)

@app.route('/api/secret', methods=['GET'])
def get_secrets():
    """Endpoint pour récupérer les messages cachés enregistrés"""
    try:
        with open('secrets.txt', 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"secrets": content})
    except FileNotFoundError:
        return jsonify({"secrets": "Aucun message caché enregistré"})

if __name__ == '__main__':
    print("\n🕵️ Serveur Flask avec messages cachés démarré!")
    print("📍 URL principale: http://localhost:5000")
    print("📍 URL avec sous-domaine: http://aGVsbG8=.localhost:5000 (hello en base64)")
    print("📍 URL avec sous-domaine: http://d29ybGQ=.localhost:5000 (world en base64)")
    print("📍 Fichier secrets.txt créé pour enregistrer les messages décodés\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
