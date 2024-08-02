from bson.objectid import*
from ..Models.user import User
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt

def signupUser():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')

    # Check if username already exists
    if username in User:
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password before storing it
    hashed_password = Bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Create a new user
    new_user = {'name': name, 'password': hashed_password}
    
    # Assign a user ID (You might need to handle this with a database)
    User_id = len(signupUser) + 1
    signupUser[username] = {'user_id': User_id, 'name': name, 'password': hashed_password}

    return jsonify({'message': 'User registered successfully'}), 201


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
