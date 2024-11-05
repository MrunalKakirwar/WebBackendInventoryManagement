# routes/inventory.py
from flask import Blueprint, request, jsonify, session
from datetime import datetime
from utils import db
from model import Inventory
from logger import log_action

inventory_blueprint = Blueprint('inventory', __name__)

def get_current_user_id():
    return session.get('user_id')

@inventory_blueprint.route('/inventory', methods=['POST'])
def create_item():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({
            "status": "failed",
            "message": "Unauthorized",
            "timestamp": datetime.utcnow()
        }), 403

    data = request.json
    new_item = Inventory(
        user_id=user_id,
        item_name=data['item_name'],
        description=data['description'],
        quantity=data['quantity'],
        price=data['price']
    )
    db.session.add(new_item)
    db.session.commit()

    # Log action
    log_action(user_id, new_item.id, "create")

    return jsonify({
        "status": "successful",
        "message": "Item created successfully!",
        "item_id": new_item.id,
        "timestamp": datetime.utcnow()
    }), 201

@inventory_blueprint.route('/inventory', methods=['GET'])
def get_all_items():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({
            "status": "failed",
            "message": "Unauthorized",
            "timestamp": datetime.utcnow()
        }), 403

    items = Inventory.query.filter_by(user_id=user_id).all()
    item_list = [{
        "id": item.id,
        "item_name": item.item_name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    } for item in items]

    return jsonify({
        "status": "successful",
        "message": "Items retrieved successfully!",
        "items": item_list,
        "timestamp": datetime.utcnow()
    })

@inventory_blueprint.route('/inventory/<int:item_id>', methods=['GET'])
def get_item(item_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({
            "status": "failed",
            "message": "Unauthorized",
            "timestamp": datetime.utcnow()
        }), 403

    item = Inventory.query.filter_by(id=item_id, user_id=user_id).first()
    if not item:
        return jsonify({
            "status": "failed",
            "message": "Item not found",
            "timestamp": datetime.utcnow()
        }), 404

    return jsonify({
        "status": "successful",
        "message": "Item retrieved successfully!",
        "item": {
            "id": item.id,
            "item_name": item.item_name,
            "description": item.description,
            "quantity": item.quantity,
            "price": item.price
        },
        "timestamp": datetime.utcnow()
    })

@inventory_blueprint.route('/inventory/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({
            "status": "failed",
            "message": "Unauthorized",
            "timestamp": datetime.utcnow()
        }), 403

    item = Inventory.query.filter_by(id=item_id, user_id=user_id).first()
    if not item:
        return jsonify({
            "status": "failed",
            "message": "Item not found",
            "timestamp": datetime.utcnow()
        }), 404

    data = request.json
    item.item_name = data.get('item_name', item.item_name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)
    db.session.commit()

    # Log action
    log_action(user_id, item_id, "update")

    return jsonify({
        "status": "successful",
        "message": "Item updated successfully!",
        "item_id": item_id,
        "timestamp": datetime.utcnow()
    })

@inventory_blueprint.route('/inventory/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({
            "status": "failed",
            "message": "Unauthorized",
            "timestamp": datetime.utcnow()
        }), 403

    item = Inventory.query.filter_by(id=item_id, user_id=user_id).first()
    if not item:
        return jsonify({
            "status": "failed",
            "message": "Item not found",
            "timestamp": datetime.utcnow()
        }), 404

    db.session.delete(item)
    db.session.commit()

    # Log action
    log_action(user_id, item_id, "delete")

    return jsonify({
        "status": "successful",
        "message": "Item deleted successfully!",
        "item_id": item_id,
        "timestamp": datetime.utcnow()
    })