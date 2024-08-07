from bson.objectid import*
from ..Models. user import User_Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta


def register_admin(username, password, email):
    # Add logic to handle admin registration, e.g., assign special roles or permissions
    # For simplicity, this function just creates an admin user with the same process as regular users
    user_data = {
        'username': username,
        'email': email,
        'password': password,
        'role': 'admin'
    }
    result = User_Admin.create_user(user_data)
    return result

def register_user(username, password, email):
    # Add logic to handle regular user registration
    user_data = {
        'username': username,
        'email': email,
        'password': password,
        'role': 'user'
    }
    result = User_Admin.create_user(user_data)
    return result

def signup():
    # Extract user data from request
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    role = request.json.get('role')

    # Validate input
    if not username or not email or not password or not role:
        return jsonify({
            'message': 'Username, email, password, and role are required',
            'username': username,
            'email': email
        }), 400

    # Hash the password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Register the user based on their role
    if role == 'admin':
        user_id = register_admin(username, hashed_password, email)
    else:
        user_id = register_user(username, hashed_password, email)

    # Generate a JWT
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, os.environ.get('SECRET_KEY'), algorithm='HS256')

    # Return the token to the client
    return jsonify({'token': token.decode('utf-8')}), 201


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

def register_admin(username, password, email):
    # Implement your admin registration logic here
         user_data = {
        'username': username,
        'email': email,
        'password': password,
        'role': 'admin'
    }
         result = User_Admin.create_user(user_data)
         return result==1       
    # and return the admin's unique identifier (e.g., admin ID)
         

def register_user(username, password, email):
    # Implement your user registration logic here
        user_data = {
        'username': username,
        'email': email,
        'password': password,
        'role': 'admin'
    }
        result = User_Admin.create_user(user_data)
        return result==2
    # and return the user's unique identifier (e.g., user ID)
    




    


