from .. import mongo
from flask import jsonify

class User:
   
    
    def create_user(new_user):
        try:
            # Insert the new user document into the 'users' collection
            result = mongo.db.user.insert_one(new_user)
            return jsonify(result)
        
        except Exception as e:
            # Handle any errors that occur during the insert operation
            print(f"Error creating user: {e}")
            return jsonify({'message': 'Error creating user'}), 500
        
        
     
    def find_user_by_username(username):
        existing_user = mongo.db.users.find_one({'username': username})
        return existing_user
       