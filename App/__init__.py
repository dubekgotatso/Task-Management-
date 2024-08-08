from .config import Config
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_pymongo import PyMongo
import jwt

mongo = PyMongo()

jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    mongo.init_app(app)
    
    jwt.init_app(app)
    
    with app.app_context():
     from .Routes import user_routes, admin_routes
    
     app.register_blueprint(user_routes.app)
     app.register_blueprint(admin_routes.app)

        
    return app