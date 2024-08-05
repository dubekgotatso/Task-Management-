from bson.objectid import*
from ..Models.admin import Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt

def signupAdmin():
    
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Check if user already exists
    existing_user = Admin.find_user_by_username(username)
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    # Create new user
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = Admin.create_user(username, email, hashed_password)
    
    if not new_user:
        return jsonify({'message': 'Failed to create user'}), 500

    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({'message': 'User created successfully', 'access_token': access_token}), 201

def loginAdmin():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Retrieve user from database (adjust based on your implementation)
    user = Admin.find_user_by_username(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    
    return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
        