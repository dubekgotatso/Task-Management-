from .. import mongo
from werkzeug.security import generate_password_hash

class User:
   
       def find_user_by_username(username):
        # Implement your logic to find a user by username from the database
        existing_user = mongo.db.signup.find_one({'username': username})
        return existing_user

    
       def create_user(username, email, password):
        existing_user = User.find_user_by_username(username)
        if existing_user:
            return None  # User already exists
        else:
            # Insert the new user into the database
            new_user = {'username': username, 'email': email, 'password': password}
            mongo.db.signup.insert_one(new_user)
            return new_user
       