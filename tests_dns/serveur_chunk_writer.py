from flask import Flask, request, jsonify
import os
import json

app = Flask(__name__)

# Configuration
UPLOAD_DIR = 'uploads'
CHUNK_FILE = os.path.join(UPLOAD_DIR, 'received_chunks.txt')

# Créer le dossier uploads s'il n'existe pas
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/write_chunk', methods=['POST'])
def write_chunk():
    """Écrit un chunk de données dans un fichier"""
    try:
        # Récupérer les données du POST
        data = request.get_json()
        print("coucou")
        if not data or 'chunk' not in data:
            return jsonify({"error": "Données manquantes"}), 400
        
        chunk = data['chunk']
        chunk_index = data.get('index', 0)
        
        # Écrire le chunk dans le fichier
        with open(CHUNK_FILE, 'a', encoding='utf-8') as f:
            f.write(chunk)
        
        print(f"Chunk {chunk_index} écrit: {chunk}")
        
        return jsonify({
            "success": True,
            "message": f"Chunk {chunk_index} écrit avec succès",
            "chunk": chunk
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/write_chunk_binary', methods=['POST'])
def write_chunk_binary():
    """Écrit des données binaires directement dans un fichier"""
    try:
        # Récupérer les données brutes du POST
        chunk = request.get_data()
        
        if not chunk:
            return jsonify({"error": "Données manquantes"}), 400
        
        # Écrire le chunk dans le fichier (mode binaire)
        with open(CHUNK_FILE, 'ab') as f:
            f.write(chunk)
        
        print(f"Chunk binaire écrit: {len(chunk)} bytes")
        
        return jsonify({
            "success": True,
            "message": f"Chunk binaire écrit avec succès",
            "size": len(chunk)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_file', methods=['GET'])
def get_file():
    """Récupère le contenu complet du fichier"""
    try:
        if os.path.exists(CHUNK_FILE):
            with open(CHUNK_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({"content": content})
        else:
            return jsonify({"content": ""})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/clear_file', methods=['POST'])
def clear_file():
    """Efface le contenu du fichier"""
    try:
        if os.path.exists(CHUNK_FILE):
            os.remove(CHUNK_FILE)
        return jsonify({"success": True, "message": "Fichier effacé"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("\n🚀 Serveur Chunk Writer démarré!")
    print("📍 POST /write_chunk - Écrire un chunk texte")
    print("📍 POST /write_chunk_binary - Écrire un chunk binaire")
    print("📍 GET /get_file - Lire le fichier complet")
    print("📍 POST /clear_file - Effacer le fichier")
    print("📍 Fichier de sortie:", CHUNK_FILE)
    print("\n")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
