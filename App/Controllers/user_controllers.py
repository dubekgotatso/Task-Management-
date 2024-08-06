from bson.objectid import*
from ..Models. user import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt




def signup_user():
    if request.method == 'POST':
        username = request.json.get('username')
        email = request.json.get('email')
        password = request.json.get('password')
        
        if not username or not email or not password:
            return jsonify({'message': 'Username, email, and password are required'}), 400
        
        # Hash the password using Werkzeug's generate_password_hash()
        hashed_password = generate_password_hash(password)
        
        # Added the 'contact' field
        new_user = {'username': username, 'email': email, 'password': hashed_password}
        
        User.create_user(new_user)
        
        return jsonify(new_user)



