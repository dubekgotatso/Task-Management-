from flask import Blueprint
from ..Controllers import user_controllers

app = Blueprint('user', __name__)

app.route('/signup_user', methods=['GET', 'POST'])(user_controllers.signup)

# app.route('/login_user', methods=['GET', 'POST'])(user_controllers.login_user)