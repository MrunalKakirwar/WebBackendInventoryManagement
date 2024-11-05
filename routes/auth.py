# routes/auth.py
from flask import Blueprint, request, jsonify, session
from datetime import datetime
from utils import db, bcrypt
from model import User
from logger import log_action

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['POST'])
def register():
    data = request.json

    if not data or not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({
            "status": "failed",
            "message": "Missing required fields: username, email, and password",
            "timestamp": datetime.utcnow()
        }), 400

    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({
            "status": "failed",
            "message": "Username already exists",
            "timestamp": datetime.utcnow()
        }), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Log action
    log_action(new_user.id, None, "register")

    return jsonify({
        "status": "successful",
        "message": "User registered successfully!",
        "timestamp": datetime.utcnow()
    }), 201

@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        session['user_id'] = user.id  # Store user ID in session
        log_action(user.id, None, "login")  # Log login action

        return jsonify({
            "status": "successful",
            "message": "Login successful!",
            "timestamp": datetime.utcnow()
        })
    return jsonify({
        "status": "failed",
        "message": "Invalid credentials",
        "timestamp": datetime.utcnow()
    }), 401

@auth_blueprint.route('/logout', methods=['POST'])
def logout():
    user_id = session.pop('user_id', None)
    if user_id:
        log_action(user_id, None, "logout")  # Log logout action

    return jsonify({
        "status": "successful",
        "message": "Logged out successfully!",
        "timestamp": datetime.utcnow()
    })
