from flask import Flask
from flask_pymongo import PyMongo
from .config import Config

mongo = PyMongo()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # initializes the PyMongo instance with the Flask application, allowing the application to use the MongoDB database.
    mongo.init_app(app)
    
    with app.app_context():
            return app