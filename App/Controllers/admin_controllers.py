from bson.objectid import*
from ..Models.admin import Admin
import re
from flask import Flask, jsonify, session, request, redirect, url_for, flash, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt

def signup():
    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validate email format
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash('Invalid email format. Please try again.', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        signupdetails = {'username': username, 'email': email, 'password': password}
        if not Admin.create_user(signupdetails):
            flash('Email or username already exists. Please try again with different credentials.', 'error')
            return redirect(url_for('user.login'))
        