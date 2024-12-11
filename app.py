from flask import Flask, request, jsonify, session
from datetime import datetime
from config import Config
from mysqldb import create_inventory_item, fetch_all_inventory_items, fetch_inventory_item, update_inventory_item, delete_inventory_item
from auth import auth_blueprint

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register Blueprints
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app

app = create_app()

@app.route('/inventory', methods=['POST'])
def create_item():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "failed", "message": "Unauthorized"}), 403

        data = request.json
        errors = []
        
        if 'item_name' not in data or not isinstance(data['item_name'], str) or not (3 <= len(data['item_name']) <= 100):
            errors.append("Item name must be a string between 3 and 100 characters.")

        if 'description' in data and (not isinstance(data['description'], str) or len(data['description']) > 500):
            errors.append("Description must be a string up to 500 characters.")

        if 'quantity' not in data or not isinstance((data['quantity']), int) or data['quantity'] < 0:
            errors.append("Quantity must be a non-negative integer.")

        if 'price' not in data or not (isinstance(data['price'], float) or isinstance(data['price'], float)) or data['price'] < 0:
            errors.append("Price must be a non-negative number.")

        if errors:
            return jsonify({
                "status": "failed",
                "message": "Validation errors",
                "errors": errors,
                "timestamp": datetime.now()
            }), 400

        if errors:
            return jsonify({"status": "failed", "message": "Validation errors", "errors": errors}), 400

        item_id = create_inventory_item(user_id, data)
        return jsonify({"status": "successful", "message": "Item created successfully!", "item_id": item_id}), 201
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error: {e}"}), 500

@app.route('/inventory', methods=['GET'])
def get_all_items():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "failed", "message": "Unauthorized"}), 403

        items = fetch_all_inventory_items(user_id)
        return jsonify({"status": "successful", "items": items}), 200
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error: {e}"}), 500

@app.route('/inventory/<item_id>', methods=['GET'])
def get_item(item_id):
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "failed", "message": "Unauthorized"}), 403

        item = fetch_inventory_item(item_id, user_id)
        if not item:
            return jsonify({"status": "failed", "message": "Item not found"}), 404

        return jsonify({"status": "successful", "item": item}), 200
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error: {e}"}), 500

@app.route('/inventory/<item_id>', methods=['PUT'])
def update_item(item_id):
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "failed", "message": "Unauthorized"}), 403

        data = request.json

        errors = []
        
        if 'item_name' in data and not isinstance(data['item_name'], str) or not (3 <= len(data['item_name']) <= 100):
            errors.append("Item name must be a string between 3 and 100 characters.")

        if 'description' in data and (not isinstance(data['description'], str) or len(data['description']) > 500):
            errors.append("Description must be a string up to 500 characters.")

        if 'quantity' in data and not isinstance((data['quantity']), int) or data['quantity'] < 0:
            errors.append("Quantity must be a non-negative integer.")

        if 'price' in data and  not (isinstance(data['price'], float) or isinstance(data['price'], float)) or data['price'] < 0:
            errors.append("Price must be a non-negative number.")

        if errors:
            return jsonify({
                "status": "failed",
                "message": "Validation errors",
                "errors": errors,
                "timestamp": datetime.now()
            }), 400



        updated = update_inventory_item(item_id, user_id, data)

        if not updated:
            return jsonify({"status": "failed", "message": "Item not found"}), 404

        return jsonify({"status": "successful", "message": "Item updated successfully!"}), 200
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error: {e}"}), 500

@app.route('/inventory/<item_id>', methods=['DELETE'])
def delete_item(item_id):
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "failed", "message": "Unauthorized"}), 403

        deleted = delete_inventory_item(item_id, user_id)

        if not deleted:
            return jsonify({"status": "failed", "message": "Item not found"}), 404

        return jsonify({"status": "successful", "message": "Item deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"status": "failed", "message": f"Error: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
