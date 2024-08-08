from bson.objectid import*
from ..Models. user import User_Admin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, session, request, redirect, url_for,flash, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt


def signup():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    
    # Here We Will Set The Default Role To User 
    role = data.get('role', 'user')

    if User_Admin.find_by_email(email):
        return jsonify({"msg": "User already exists"}), 409
    
    hashed_password = generate_password_hash(password)
    new_user = User_Admin(email=email, username=username, password=hashed_password, role=role)
    new_user.save()

    return jsonify({"msg": "User signed up successfully"}), 201


def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User_Admin.find_by_email(email)
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity={"email": user.email, "role": user.role})
        return jsonify({"access token": access_token ,"role": user.role,"password":user.password} ), 200

    return jsonify({"msg": "Invalid credentials"}), 401

    




    


