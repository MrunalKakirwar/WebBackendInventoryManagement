from flask import Blueprint, request, jsonify, session
from datetime import datetime
from utils import db, bcrypt
from model import User
from logger import log_action

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        # Error handling
        if not data or not all(key in data for key in ['username', 'email', 'password']):
            return jsonify({
                "status": "failed",
                "message": "Missing required fields: username, email, and password",
                "timestamp": datetime.now()
            }), 400

        # Error handling
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return jsonify({
                "status": "failed",
                "message": "Username already exists",
                "timestamp": datetime.now()
            }), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Log action to the history table
        log_action(new_user.id, None, "register")

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
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            session['user_id'] = user.id  # Store user ID in session
            log_action(user.id, None, "login")  # Log login action

            return jsonify({
                "status": "successful",
                "message": "Login successful!",
                "timestamp": datetime.now()
            })
        
        # Error handling
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
            log_action(user_id, None, "logout")  # Log logout action

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
