from bson.objectid import*
from ..Models. user import User_Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta


def signup_user():
    if request.method == 'POST':
        username = request.json.get('username')
        contact = request.json.get('contact')
        email = request.json.get('email')
        password = request.json.get('password')
        
        if not username or not email or not password:
            return jsonify({'message': 'Username, email, and password are required'}), 400
        
        # Hash the password using Werkzeug's generate_password_hash()
        hashed_password = generate_password_hash(password)
        
        # Added the 'contact' field
        new_user = {'username': username, 'contact': contact, 'email': email, 'password': hashed_password}
        
        User_Admin.create_user(new_user)
        
        return jsonify(new_user)


def login():
    # Extract user data from request
    username = request.json.get('username')
    password = request.json.get('password')

    # Fetch user from database
    user = User_Admin.find_user_by_username(username=username).first()

    # Verify password
    if user and check_password_hash(user.password, password):
        # Generate a JWT
        payload = {
            'user_id': user.id,
            'role': user.role,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, os.environ.get('SECRET_KEY'), algorithm='HS256')

        # Return the token to the client
        return jsonify({'token': token.decode('utf-8')}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

    




    


