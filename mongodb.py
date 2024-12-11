from pymongo import MongoClient
from config import Config
from bson.objectid import ObjectId
from datetime import datetime

# MongoDB Database Connection
def get_db_connection():
    client = MongoClient(Config.MONGO_URI)
    return client[Config.MONGO_DB_NAME]

def get_user_by_username(username):
    try:
        db = get_db_connection()
        users_collection = db['users']
        user = users_collection.find_one({"username": username})
        user['id'] = str(user['_id'])
        return user
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def insert_new_user(username, email, password_hash):
    try:
        db = get_db_connection()
        users_collection = db['users']
        user_data = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        result = users_collection.insert_one(user_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error inserting new user: {e}")
        return None

def create_inventory_item(user_id, data):
    try:
        db = get_db_connection()
        inventory_collection = db['inventory']
        item = {
            "user_id": user_id,
            "item_name": data['item_name'],
            "description": data.get('description', ''),
            "quantity": data['quantity'],
            "price": data['price']
        }
        result = inventory_collection.insert_one(item)
        return str(result.inserted_id)
    except Exception as e:
        raise Exception(f"Error creating inventory item: {e}")

def serialize_item(item):
    return {
        "id": str(item["_id"]),
        "user_id": item["user_id"],
        "item_name": item["item_name"],
        "description": item.get("description", ""),
        "quantity": item["quantity"],
        "price": item["price"],
    }

def fetch_all_inventory_items(user_id):
    try:
        db = get_db_connection()
        inventory_collection = db['inventory']
        items = list(inventory_collection.find({"user_id": user_id}))
        items = [ serialize_item(item) for item in items]
        return items
    except Exception as e:
        raise Exception(f"Error fetching all inventory items: {e}")

def fetch_inventory_item(item_id, user_id):
    try:
        db = get_db_connection()
        inventory_collection = db['inventory']
        try:
            item_id = ObjectId(item_id)
        except Exception:
            return Exception("Invalid item ID format")

        item = inventory_collection.find_one({"_id": item_id, "user_id": user_id})
        item = serialize_item(item)
        return item
    except Exception as e:
        raise Exception(f"Error fetching inventory item: {e}")

def update_inventory_item(item_id, user_id, data):
    try:
        db = get_db_connection()
        inventory_collection = db['inventory']
        update_fields = {}

        try:
            item_id = ObjectId(item_id)
        except Exception:
            return Exception("Invalid item ID format")


        if 'item_name' in data:
            update_fields['item_name'] = data['item_name']
        if 'description' in data:
            update_fields['description'] = data['description']
        if 'quantity' in data:
            update_fields['quantity'] = data['quantity']
        if 'price' in data:
            update_fields['price'] = data['price']

        result = inventory_collection.update_one(
            {"_id": item_id, "user_id": user_id},
            {"$set": update_fields}
        )
        return result.matched_count > 0
    except Exception as e:
        raise Exception(f"Error updating inventory item: {e}")

def delete_inventory_item(item_id, user_id):
    try:
        db = get_db_connection()
        inventory_collection = db['inventory']
        try:
            item_id = ObjectId(item_id)
        except Exception:
            return Exception("Invalid item ID format")

        result = inventory_collection.delete_one({"_id": item_id, "user_id": user_id})
        return result.deleted_count > 0
    except Exception as e:
        raise Exception(f"Error deleting inventory item: {e}")

def log_action(user_id, item_id, action_type):
    try:
        db = get_db_connection()
        history_collection = db['history']

        history_entry = {
            "user_id": user_id,
            "item_id": item_id,
            "action_type": action_type,
            "timestamp": datetime.now()
        }

        history_collection.insert_one(history_entry)

    except Exception as e:
        print(f"Error logging action: {e}")