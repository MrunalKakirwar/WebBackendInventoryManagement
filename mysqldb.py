import mysql.connector
from config import Config
from datetime import datetime

def get_db_connection():
    return mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )
def get_user_by_username(username):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        return user
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def insert_new_user(username, email, password_hash):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, password_hash)
        )
        connection.commit()
        user_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return user_id
    except Exception as e:
        print(f"Error inserting new user: {e}")
        return None


def create_inventory_item(user_id, data):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO inventory (user_id, item_name, description, quantity, price) VALUES (%s, %s, %s, %s, %s)",
            (user_id, data['item_name'], data.get('description', ''), data['quantity'], data['price'])
        )
        connection.commit()
        item_id = cursor.lastrowid
        cursor.close()
        connection.close()
        return item_id
    except Exception as e:
        raise Exception(f"Error creating inventory item: {e}")

def fetch_all_inventory_items(user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM inventory WHERE user_id = %s", (user_id,))
        items = cursor.fetchall()
        cursor.close()
        connection.close()
        return items
    except Exception as e:
        raise Exception(f"Error fetching all inventory items: {e}")

def fetch_inventory_item(item_id, user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM inventory WHERE id = %s AND user_id = %s", (item_id, user_id))
        item = cursor.fetchone()
        cursor.close()
        connection.close()
        return item
    except Exception as e:
        raise Exception(f"Error fetching inventory item: {e}")

def update_inventory_item(item_id, user_id, data):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM inventory WHERE id = %s AND user_id = %s", (item_id, user_id))
        item = cursor.fetchone()
        if not item:
            return False
        cursor.execute(
            "UPDATE inventory SET item_name = %s, description = %s, quantity = %s, price = %s WHERE id = %s AND user_id = %s",
            (data.get('item_name', item['item_name']), data.get('description', item['description']),
             data.get('quantity', item['quantity']), data.get('price', item['price']), item_id, user_id)
        )
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        raise Exception(f"Error updating inventory item: {e}")

def delete_inventory_item(item_id, user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM inventory WHERE id = %s AND user_id = %s", (item_id, user_id))
        if cursor.rowcount == 0:
            return False
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        raise Exception(f"Error deleting inventory item: {e}")



def log_action(user_id, item_id, action_type):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "INSERT INTO history (user_id, item_id, action_type, timestamp) VALUES (%s, %s, %s, %s)",
            (user_id, item_id, action_type, datetime.now())
        )
        connection.commit()

        cursor.close()
        connection.close()
    except Exception as e:
        print(f"Error logging action: {e}")

def get_history():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM history ORDER BY timestamp DESC")
        history = cursor.fetchall()
        
        cursor.close()
        connection.close()
        return history
    except Exception as e:
        raise Exception(f"Error fetching history: {e}")
