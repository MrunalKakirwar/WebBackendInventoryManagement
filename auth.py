import re
from flask import Blueprint, request, jsonify, session
from datetime import datetime
from mysqldb import get_user_by_username, insert_new_user, log_action
from werkzeug.security import generate_password_hash, check_password_hash

auth_blueprint = Blueprint('auth', __name__)

def validate_user_data(data):
    errors = []

    if 'username' not in data or not isinstance(data['username'], str) or not (3 <= len(data['username']) <= 30):
        errors.append("Username must be a string between 3 and 30 characters.")
    elif not re.match(r"^[a-zA-Z0-9_]+$", data['username']):
        errors.append("Username can only contain letters, numbers, and underscores.")

    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if 'email' not in data or not isinstance(data['email'], str) or not re.match(email_regex, data['email']):
        errors.append("Invalid email format.")

    if 'password' not in data or not isinstance(data['password'], str) or len(data['password']) < 8:
        errors.append("Password must be at least 8 characters long.")
    elif not re.search(r"[A-Za-z]", data['password']) or not re.search(r"[0-9]", data['password']):
        errors.append("Password must contain at least one letter and one number.")

    return errors

@auth_blueprint.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        errors = validate_user_data(data)

        if errors:
            return jsonify({
                "status": "failed",
                "message": "Validation errors",
                "errors": errors,
                "timestamp": datetime.now()
            }), 400

        existing_user = get_user_by_username(data['username'])

        if existing_user:
            return jsonify({
                "status": "failed",
                "message": "Username already exists",
                "timestamp": datetime.now()
            }), 400

        hashed_password = generate_password_hash(data['password'])
        user_id = insert_new_user(data['username'], data['email'], hashed_password)

        log_action(user_id, None, "register")

        return jsonify({
            "status": "successful",
            "message": "User registered successfully!",
            "timestamp": datetime.now()
        }), 201
    except Exception as e:
        return jsonify({
            "status": "failed",
            "message": f"Error: {e}",
            "timestamp": datetime.now()
        }), 500

@auth_blueprint.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = get_user_by_username(data['username'])

        if user and check_password_hash(user['password_hash'], data['password']):
            session['user_id'] = user['id']
            log_action(user['id'], None, "login")

            return jsonify({
                "status": "successful",
                "message": "Login successful!",
                "timestamp": datetime.now()
            })

        return jsonify({
            "status": "failed",
            "message": "Invalid credentials",
            "timestamp": datetime.now()
        }), 401
    except Exception as e:
        return jsonify({
            "status": "failed",
            "message": f"Error: {e}",
            "timestamp": datetime.now()
        }), 500

@auth_blueprint.route('/logout', methods=['POST'])
def logout():
    try:
        user_id = session.pop('user_id', None)

        if user_id:
            log_action(user_id, None, "logout")

        return jsonify({
            "status": "successful",
            "message": "Logged out successfully!",
            "timestamp": datetime.now()
        })
    except Exception as e:
        return jsonify({
            "status": "failed",
            "message": f"Error: {e}",
            "timestamp": datetime.now()
        }), 500
