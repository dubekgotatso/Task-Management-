from .config import Config
from flask import Flask
from flask_pymongo import PyMongo

mongo = PyMongo()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    mongo.init_app(app)
    with app.app_context():
     from .Routes import user_routes, admin_routes
    
     app.register_blueprint(user_routes.app)
     app.register_blueprint(admin_routes.app)

        
    return app