from flask import Flask, request, jsonify, redirect, send_from_directory
app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400
    file.save(f"./received_{file.filename}")
    return jsonify({"status": f"Received {file.filename}"}), 200

@app.route("/")
def index():
    return redirect("/index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory(".", path)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
