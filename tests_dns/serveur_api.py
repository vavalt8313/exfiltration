from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
import cgi

class CORSRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {"message": "Serveur API fonctionne!"}
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            print(f"Données reçues: {data}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {"status": "success", "received": data}
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            self.send_error(400, f"Erreur: {str(e)}")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

HOST = 'localhost'
PORT = 8000

def run_api_server():
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, CORSRequestHandler)
    print(f"Serveur API démarré sur http://{HOST}:{PORT}")
    print("Endpoints disponibles:")
    print("  GET  / - Test de connexion")
    print("  POST / - Envoi de données")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur...")
    finally:
        httpd.server_close()

if __name__ == '__main__':
    run_api_server()
