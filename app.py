# app.py
from flask import Flask
from config import Config
from utils import db, bcrypt, session  # Import initialized extensions

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions with the app instance
    db.init_app(app)
    bcrypt.init_app(app)
    session.init_app(app)

    # Register blueprints
    from routes.auth import auth_blueprint
    from routes.inventory import inventory_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(inventory_blueprint)


    return app

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)