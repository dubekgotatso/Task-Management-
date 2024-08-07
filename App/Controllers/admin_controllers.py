from bson.objectid import*
from ..Models.admin import Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt

def signup_admin():
        user_data={
        'username' : request.json.get('username'),
        'email' :request.json.get('email'),
        'password' : request.json.get('password')
    }
    
        Admin.create_user(user_data)
        return ({"message": "Successfully signup"})
        
        
def login_admin():
        username = request.json.get('username')
        password = request.json.get('password')
        
        Admin.find_user_by_username(username, password)
        # User authentication logic here

    # If authentication successful
    # Generate and return a token as a response
        return jsonify({'token': 'your_generated_token_here'})