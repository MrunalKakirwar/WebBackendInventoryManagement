from flask import Flask, request, jsonify, session, redirect, url_for # type: ignore
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Please provide both username and password"}), 400

    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Please provide both username and password"}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        session['user_id'] = user.id
        session.permanent = True  # Make the session permanent
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logout successful"}), 200

@app.route('/inventory', methods=['GET'])
def get_inventory():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    items = InventoryItem.query.filter_by(user_id=session['user_id']).all()
    return jsonify([{"id": item.id, "name": item.name, "description": item.description, "quantity": item.quantity, "price": item.price} for item in items])

@app.route('/inventory/<int:item_id>', methods=['GET'])
def get_inventory_item(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if item is None:
        return jsonify({"error": "Item not found"}), 404
    return jsonify({"id": item.id, "name": item.name, "description": item.description, "quantity": item.quantity, "price": item.price})

@app.route('/inventory', methods=['POST'])
def create_inventory_item():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    if not data or 'name' not in data or 'quantity' not in data or 'price' not in data:
        return jsonify({"error": "Please provide name, quantity, and price"}), 400

    if not isinstance(data['quantity'], int) or data['quantity'] <= 0:
        return jsonify({"error": "Quantity must be a positive integer"}), 400
    if not isinstance(data['price'], (int, float)) or data['price'] <= 0:
        return jsonify({"error": "Price must be a positive number"}), 400

    new_item = InventoryItem(name=data['name'], description=data.get('description', ''), quantity=data['quantity'], price=data['price'], user_id=session['user_id'])
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"message": "Item created successfully", "item": {"id": new_item.id, "name": new_item.name}}), 201

@app.route('/inventory/<int:item_id>', methods=['PUT'])
def update_inventory_item(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if item is None:
        return jsonify({"error": "Item not found"}), 404

    data = request.json
    if 'quantity' in data and (not isinstance(data['quantity'], int) or data['quantity'] <= 0):
        return jsonify({"error": "Quantity must be a positive integer"}), 400
    if 'price' in data and (not isinstance(data['price'], (int, float)) or data['price'] <= 0):
        return jsonify({"error": "Price must be a positive number"}), 400

    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)
    db.session.commit()
    return jsonify({"message": "Item updated successfully", "item": {"id": item.id, "name": item.name}})

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
def delete_inventory_item(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if item is None:
        return jsonify({"error": "Item not found"}), 404

    db.session.delete(item)
    db.session.commit()
    return '', 204

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
