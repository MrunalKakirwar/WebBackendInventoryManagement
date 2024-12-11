import os
from datetime import timedelta

class Config:
    # General Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SESSION_TYPE = 'filesystem'
    SESSION_COOKIE_SECURE = True 
    SESSION_COOKIE_HTTPONLY = True  
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # MySQL Database Configuration
    DB_HOST = os.environ.get('DB_HOST') or '127.0.0.1'
    DB_USER = os.environ.get('DB_USER') or 'sarita'
    DB_PASSWORD = os.environ.get('DB_PASSWORD') or 'admin'
    DB_NAME = os.environ.get('DB_NAME') or 'inventory'

    # MongoDB Configuration
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb+srv://admin:admin@cluster0.zqiv3.mongodb.net/'
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME') or 'inventory_db'