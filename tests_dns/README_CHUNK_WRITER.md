# Chunk Writer via POST - Guide d'utilisation

Cette solution permet d'écrire des chunks de données directement dans un fichier sur le serveur en utilisant la méthode POST.

## Architecture

- **serveur_chunk_writer.py** : Serveur Flask avec routes POST dédiées
- **site_chunk_writer.html** : Interface web pour envoyer les chunks
- **uploads/received_chunks.txt** : Fichier de sortie contenant tous les chunks

## Installation et démarrage

### 1. Démarrer le serveur
```bash
python serveur_chunk_writer.py
```
Le serveur démarre sur le port 5001.

### 2. Ouvrir l'interface web
Ouvrez `site_chunk_writer.html` dans votre navigateur ou accédez à :
```
http://localhost:5001/site_chunk_writer.html
```

## Routes API disponibles

### POST /write_chunk
Écrit un chunk texte dans le fichier.
```json
POST /write_chunk
Content-Type: application/json

{
    "chunk": "texte du chunk",
    "index": 0
}
```

### POST /write_chunk_binary
Écrit des données binaires dans le fichier.
```bash
POST /write_chunk_binary
Content-Type: application/octet-stream
[données binaires]
```

### GET /get_file
Récupère le contenu complet du fichier.

### POST /clear_file
Efface le contenu du fichier.

## Exemple d'utilisation avec JavaScript

```javascript
// Envoyer un chunk via fetch
const response = await fetch('http://localhost:5001/write_chunk', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        chunk: 'Hello World',
        index: 1
    })
});

const result = await response.json();
console.log(result);
```

## Exemple d'utilisation avec curl

```bash
# Envoyer un chunk texte
curl -X POST http://localhost:5001/write_chunk \
  -H "Content-Type: application/json" \
  -d '{"chunk":"Hello World","index":1}'

# Envoyer des données binaires
curl -X POST http://localhost:5001/write_chunk_binary \
  --data-binary "Hello World"

# Lire le fichier
curl http://localhost:5001/get_file

# Effacer le fichier
curl -X POST http://localhost:5001/clear_file
```

## Structure des fichiers

```
uploads/
└── received_chunks.txt    # Contient tous les chunks concaténés
```

## Notes

- Le serveur écrit les chunks en mode append (ajout)
- Les données sont stockées en UTF-8 pour le texte
- Les données binaires sont stockées telles quelles
- Le fichier est créé automatiquement s'il n'existe pas
