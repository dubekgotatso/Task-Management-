from flask import Blueprint
from ..Controllers import admin_controllers

app = Blueprint('admin', __name__)

app.route('/signup_admin', methods=['GET', 'POST'])(admin_controllers.signup_admin)

# app.route('/login_admin', methods=['GET', 'POST'])(admin_controllers.loginAdmin)

