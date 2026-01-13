"""
Micro SIEM Backend Application

This module implements a Flask-based web application for security information and event management (SIEM).
It provides endpoints for user authentication, log file upload, anomaly analysis, and serving a frontend UI.

Features:
- Traditional username/password authentication
- Google OAuth integration for login
- JWT-based session management
- File upload with background analysis using ML models
- Serving analysis results and static frontend files

Dependencies:
- Flask for web framework
- Flask-CORS for cross-origin requests
- Flask-JWT-Extended for JWT token management
- Google Auth libraries for OAuth verification
- Custom log_analyzer module for anomaly detection
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import os
import datetime
import threading
import json
import logging
from dotenv import load_dotenv
from log_analyzer import analyze_log
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Load environment variables from .env file if present
load_dotenv()

# Configure logging to capture info, warnings, and errors with timestamps
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask application and enable CORS for frontend communication
app = Flask(__name__)
CORS(app)

# JWT configuration - in production, use a strong secret key from environment
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-me"
jwt = JWTManager(app)

# Google OAuth client ID from environment variables
CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')

# Set the static folder for serving built frontend files
app.static_folder = 'dist'

# Mock user database for demonstration - in production, use a proper database
USERS = {"admin": "password123"}

@app.route("/login", methods=["POST"])
def login():
    """
    Handle traditional username/password login.

    This endpoint authenticates users using a simple username/password combination.
    On successful authentication, it returns a JWT access token for subsequent requests.

    Request Body (JSON):
        - username (str): The user's username
        - password (str): The user's password

    Returns:
        JSON: {"access_token": "<jwt_token>"} on success, or {"msg": "Bad username or password"} on failure
        Status: 200 on success, 401 on authentication failure
    """
    # Extract username and password from JSON request body
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # Log the login attempt for monitoring
    logger.info(f"Login attempt for user: {username}")

    # Check if credentials match the mock user database
    if username not in USERS or USERS[username] != password:
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"msg": "Bad username or password"}), 401

    # Generate JWT access token with username as identity
    access_token = create_access_token(identity=username)
    logger.info(f"Successful login for user: {username}")
    return jsonify(access_token=access_token)

@app.route("/google_login", methods=["POST"])
def google_login():
    """
    Handle Google OAuth login.

    This endpoint verifies a Google ID token obtained from the frontend Google Sign-In.
    If the token is valid, it creates a JWT access token for the application.

    Request Body (JSON):
        - token (str): The Google ID token from the frontend

    Returns:
        JSON: {"access_token": "<jwt_token>"} on success
        Status: 200 on success, 400 if no token, 401 if invalid token
    """
    # Extract the Google ID token from the request
    token = request.json.get("token", None)
    if not token:
        logger.warning("Google login attempt without token")
        return jsonify({"msg": "No token provided"}), 400

    try:
        # Verify the token with Google's servers using the client ID
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)
        logger.info(f"Google login successful for user: {idinfo['email']}")

        # On successful verification, create a local JWT token using the email as identity
        access_token = create_access_token(identity=idinfo['email'])
        return jsonify(access_token=access_token)
    except ValueError as e:
        # Token verification failed
        logger.warning(f"Google login failed: {str(e)}")
        return jsonify({"msg": "Invalid token"}), 401

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    """
    Protected endpoint that requires authentication.

    This endpoint demonstrates JWT-protected routes. It returns the current user's identity.

    Requires: Valid JWT access token in Authorization header

    Returns:
        JSON: {"logged_in_as": "<username>", "message": "Welcome to the secure zone!"}
        Status: 200 on success, 401 if not authenticated
    """
    # Retrieve the current user's identity from the JWT token
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user, message="Welcome to the secure zone!")

@app.route("/upload", methods=["POST"])
@jwt_required()
def upload_file():
    """
    Handle file upload for log analysis.

    This endpoint accepts log files from authenticated users, saves them to a staging directory,
    and initiates background analysis using machine learning models for anomaly detection.

    Request Form Data:
        - file: The log file to upload (multipart/form-data)

    Requires: Valid JWT access token

    Returns:
        JSON: {"msg": "File uploaded successfully", "file_id": "<filename>"}
        Status: 200 on success, 400 on file errors, 401 if not authenticated

    The analysis runs asynchronously in a background thread, and results can be retrieved
    via the /analysis/<file_id> endpoint.
    """
    # Check if the request contains a file
    if 'file' not in request.files:
        logger.error("No file part in upload request")
        return jsonify({"msg": "No file part"}), 400

    # Get the uploaded file
    file = request.files['file']

    # Verify the file has a valid filename
    if file.filename == '':
        logger.warning("Empty filename in upload")
        return jsonify({"msg": "No selected file"}), 400

    # Get the current authenticated user
    current_user = get_jwt_identity()
    logger.info(f"File upload by user: {current_user}, filename: {file.filename}")

    # Generate a unique timestamp in milliseconds for filename uniqueness
    timestamp_ms = int(datetime.datetime.now().timestamp() * 1000)

    # Define the staging directory for uploaded files
    staging_dir = os.path.join(os.path.dirname(__file__), 'data', 'staging')
    # Ensure the staging directory exists
    os.makedirs(staging_dir, exist_ok=True)

    # Create a safe, unique filename: user_base_timestamp.extension
    # This prevents conflicts and associates files with users
    original_name = file.filename
    name_parts = original_name.rsplit('.', 1)  # Split on last dot for extension
    base_name = name_parts[0]
    extension = name_parts[1] if len(name_parts) > 1 else ''
    new_filename = f"{current_user}_{base_name}_{timestamp_ms}.{extension}"

    # Save the uploaded file to the staging directory
    file_path = os.path.join(staging_dir, new_filename)
    file.save(file_path)
    logger.info(f"File saved: {file_path}")

    # Start background log analysis using a separate thread
    # This prevents the upload endpoint from blocking while analysis runs
    analysis_thread = threading.Thread(target=analyze_log, args=(file_path,))
    analysis_thread.start()
    logger.info("Log analysis started in background thread")

    # Return success response with the file identifier for later retrieval
    return jsonify({"msg": "File uploaded successfully", "file_id": new_filename}), 200

@app.route("/analysis/<file_id>", methods=["GET"])
@jwt_required()
def get_analysis(file_id):
    """
    Retrieve analysis results for a specific uploaded file.

    This endpoint returns the anomaly detection results from the background analysis.
    It ensures users can only access analysis for their own uploaded files.

    Path Parameters:
        - file_id (str): The unique file identifier returned during upload

    Requires: Valid JWT access token

    Returns:
        JSON: Analysis results containing anomalies and graphs, or {"status": "processing"}
        Status: 200 if analysis complete, 202 if still processing, 403 if unauthorized
    """
    # Get the current authenticated user
    current_user = get_jwt_identity()

    # Security check: ensure the file_id starts with the current user's name
    # This prevents users from accessing other users' analysis results
    if not file_id.startswith(current_user + '_'):
        return jsonify({"msg": "Unauthorized"}), 403

    # Construct the path to the analysis results file
    analysis_file = os.path.join(os.path.dirname(__file__), 'data', 'staging', file_id + '.analysis.json')

    # Check if the analysis file exists
    if os.path.exists(analysis_file):
        # Load and return the analysis results
        with open(analysis_file, 'r') as f:
            data = json.load(f)
        return jsonify(data), 200
    else:
        # Analysis is still in progress (file not yet written)
        return jsonify({"status": "processing"}), 202

@app.route("/analysis_file/<filename>", methods=["GET"])
def serve_analysis_file(filename):
    """
    Serve analysis-related files (e.g., generated plots).

    This endpoint serves static files like PNG graphs generated during EDA.

    Path Parameters:
        - filename (str): The name of the file to serve

    Returns:
        The requested file, or 404 if not found
    """
    return send_from_directory(os.path.join(app.root_path, 'data', 'staging'), filename)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    """
    Serve the React frontend application.

    This catch-all route serves the built React app from the 'dist' folder.
    If the requested path exists as a file, serve it directly; otherwise,
    serve the main index.html (for client-side routing).

    Path Parameters:
        - path (str): The requested path from the frontend

    Returns:
        The requested static file or index.html
    """
    # Check if the requested path exists as a static file
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        # For client-side routing, serve the main HTML file
        return send_from_directory(app.static_folder, 'index.html')

def test_app():
    """
    Test function to verify basic app functionality.

    This function runs simple tests on the Flask application endpoints
    using Werkzeug's test client. Currently tests the login endpoint.
    """
    from werkzeug.test import Client
    client = Client(app)

    # Test the login endpoint with valid credentials
    response = client.post('/login', json={'username': 'admin', 'password': 'password123'})
    print("Login test response:", response.get_json())

    # Additional tests can be added here in the future
    # e.g., testing file upload, protected routes, etc.

if __name__ == "__main__":
    # Run tests before starting the server
    test_app()

    # Start the Flask development server
    # host='0.0.0.0' allows connections from any IP (useful for containers)
    # debug=True enables debug mode with auto-reload and error pages
    app.run(host='0.0.0.0', debug=True, port=int(os.environ.get("PORT", 8080)))
