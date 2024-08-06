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
        