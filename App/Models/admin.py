from .. import mongo
from flask import jsonify
  
def create_user(new_user):
        try:
            # Insert the new user document into the 'users' collection
            result = mongo.db.user.insert_one(new_user)
            return jsonify(result)
        
        except Exception as e:
            # Handle any errors that occur during the insert operation
            print(f"Error creating user: {e}")
            return jsonify({'message': 'Error creating user'}), 500