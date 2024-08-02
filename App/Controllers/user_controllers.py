from bson.objectid import*
from ..Models.user import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt

def signup():
    # Get data from request
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Check if user already exists
    existing_user = User.create_user(username)  # Adjust based on how you find users
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    # Create new user
    hashed_password = generate_password_hash(password, method='sha256')
    new_user =  User.create_user(username, email, hashed_password)  # Adjust based on your implementation
    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({'message': 'User created successfully', 'access_token': access_token}), 201


def loginUser():
    # Extract the user ID from the JWT
    user_id = get_jwt_identity()
    user = None

    # Check if user exists in the database
    for username, data in User.items():
        if data['user_id'] == user_id:
            user = data
            break

    # Check if user exists
    if user:
        return jsonify({'message': 'User found', 'name': user['name']})
    else:
        return jsonify({'message': 'User not found'}), 404
