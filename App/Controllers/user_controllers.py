from bson.objectid import*
from ..Models. user import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt




def signup_user():
        user_data={
        'username' : request.json.get('username'),
        'email' :request.json.get('email'),
        'password' : request.json.get('password')
    }
    
        User.create_user(user_data)
        return ({"message": "Successfully signup"})
    
    
def login_user():
        username = request.json.get('username')
        password = request.json.get('password')
        
        User.find_user_by_username(username, password)
        return jsonify({""})
    


