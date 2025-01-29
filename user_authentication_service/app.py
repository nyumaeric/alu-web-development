#!/usr/bin/env python3
""" Basic Flask app """

from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)

AUTH = Auth()
app = Flask(__name__)

app.url_map.strict_slashes = False


@app.route('/')
def hello_world():
    """Hello world endpoint."""
    return jsonify({"message": "Bienvenue"})
    # Updated to match the task requirement


@app.route('/users', methods=['POST'])
def register_user():
    """Register user."""
    data = request.json  # Get the JSON data
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"error": "Missing email or password"}), 400

    email = data.get("email")
    password = data.get("password")

    # Check if the user already exists
    existing_user = AUTH.get_user_by_email(email)
    if existing_user:
        return jsonify({"error": "User already exists"}), 409  # Conflict

    user = AUTH.register_user(email, password)
    return jsonify({"email": user.email, "message": "User created"}), 201


@app.route('/sessions', methods=['POST'])
def login():
    """Login."""
    data = request.json  # Get the JSON data
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"error": "Missing email or password"}), 400

    email = data.get("email")
    password = data.get("password")

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = make_response(
                jsonify({"email": email,
                         "session_id": session_id,
                         "message": "logged in"}))
            response.set_cookie('session_id', session_id)
            return response
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/sessions', methods=['DELETE'])
def logout():
    """Logout."""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect('/')
    return jsonify({"error": "Unauthorized"}), 403


@app.route('/profile', methods=['GET'])
def profile():
    """Get profile."""
    session_id = request.cookies.get("session_id")
    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email})
    return jsonify({"error": "Unauthorized"}), 403


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """Get reset password token."""
    data = request.json  # Get the JSON data
    if not data or 'email' not in data:
        return jsonify({"error": "Missing email"}), 400

    email = data.get("email")
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token})
    except ValueError:
        return jsonify({"error": "Invalid email"}), 403


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update password."""
    data = request.json  # Get the JSON data
    if not data or \
       'email' not in data or \
       'reset_token' not in data or \
       'new_password' not in data:
        return jsonify({"error": "Missing required fields"}), 400

    email = data.get("email")
    reset_token = data.get("reset_token")
    password = data.get("new_password")
    try:
        AUTH.update_password(reset_token, password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        return jsonify({"error": "Invalid token"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
