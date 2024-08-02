from flask import Flask, jsonify, session, request, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt


app = Flask(__name__)



if __name__ == "__main__":
    with app.app_context():
        app.run(debug=True)
    
    