from flask import Flask
from config import Config
from utils import db, bcrypt, session 

def create_app():
    #Init Flask
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    session.init_app(app)

    #Register routes
    from routes.auth import auth_blueprint
    from routes.inventory import inventory_blueprint
    from routes.history import history_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(inventory_blueprint)
    app.register_blueprint(history_blueprint)


    return app

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
