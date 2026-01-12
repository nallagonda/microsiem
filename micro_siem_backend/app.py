from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import os
import datetime
import threading
import json
from dotenv import load_dotenv
from log_analyzer import analyze_log
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

load_dotenv()

app = Flask(__name__)
CORS(app)
# Configuration - In 2026, always use environment variables for secrets
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-me"
jwt = JWTManager(app)
CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')

app.static_folder = 'dist'

# Mock user database
USERS = {"admin": "password123"}

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # Validate credentials
    if username not in USERS or USERS[username] != password:
        return jsonify({"msg": "Bad username or password"}), 401

    # Create a token for the user
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/google_login", methods=["POST"])
def google_login():
    token = request.json.get("token", None)
    if not token:
        return jsonify({"msg": "No token provided"}), 400

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)
        # If valid, create Flask token using email as identity
        access_token = create_access_token(identity=idinfo['email'])
        return jsonify(access_token=access_token)
    except ValueError as e:
        return jsonify({"msg": "Invalid token"}), 401

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user, message="Welcome to the secure zone!")

@app.route("/upload", methods=["POST"])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({"msg": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400

    current_user = get_jwt_identity()
    print(f"Logged in user name is {current_user}")

    # Get timestamp in milliseconds
    timestamp_ms = int(datetime.datetime.now().timestamp() * 1000)

    # Create staging directory if it doesn't exist
    staging_dir = os.path.join(os.path.dirname(__file__), 'data', 'staging')
    os.makedirs(staging_dir, exist_ok=True)

    # Generate new filename with user prefix and timestamp suffix
    original_name = file.filename
    name_parts = original_name.rsplit('.', 1)
    base_name = name_parts[0]
    extension = name_parts[1] if len(name_parts) > 1 else ''
    new_filename = f"{current_user}_{base_name}_{timestamp_ms}.{extension}"

    # Save the file
    file_path = os.path.join(staging_dir, new_filename)
    file.save(file_path)

    # Start log analysis in a background thread
    analysis_thread = threading.Thread(target=analyze_log, args=(file_path,))
    analysis_thread.start()

    return jsonify({"msg": "File uploaded successfully", "file_id": new_filename}), 200

@app.route("/analysis/<file_id>", methods=["GET"])
@jwt_required()
def get_analysis(file_id):
    current_user = get_jwt_identity()
    # Ensure the file belongs to the user
    if not file_id.startswith(current_user + '_'):
        return jsonify({"msg": "Unauthorized"}), 403

    analysis_file = os.path.join(os.path.dirname(__file__), 'data', 'staging', file_id + '.analysis.json')
    if os.path.exists(analysis_file):
        with open(analysis_file, 'r') as f:
            data = json.load(f)
        return jsonify(data), 200
    else:
        return jsonify({"status": "processing"}), 202

@app.route("/analysis_file/<filename>", methods=["GET"])
def serve_analysis_file(filename):
    return send_from_directory(os.path.join(app.root_path, 'data', 'staging'), filename)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

def test_app():
    """Test function for app endpoints."""
    from werkzeug.test import Client
    client = Client(app)
    # Test login
    response = client.post('/login', json={'username': 'admin', 'password': 'password123'})
    print("Login test response:", response.get_json())
    # More tests can be added here

if __name__ == "__main__":
    test_app()
    app.run(host='0.0.0.0', debug=True)
