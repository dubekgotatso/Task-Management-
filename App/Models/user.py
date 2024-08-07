from .. import mongo
from flask import jsonify

class User_Admin:
   
    
    def create_user(user_data):
        return mongo.db.user.insert_one(user_data)
    
    def find_user_by_username(user_data):
        return mongo.db.user.insert_one(user_data)
    
        
        
     
   
        