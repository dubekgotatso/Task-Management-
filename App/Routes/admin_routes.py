from flask import Blueprint
from ..Controllers import admin_controllers

app = Blueprint('admin', __name__)

app.route('/signup', methods=['GET', 'POST'])(admin_controllers.signupAdmin)

