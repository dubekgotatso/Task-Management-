from flask import Blueprint
from ..Controllers import user_controllers

app = Blueprint('user', __name__)

app.route('/signup', methods=['GET', 'POST'])(user_controllers.signupUser)

app.route('/login', methods=['GET', 'POST'])(user_controllers.loginUser)