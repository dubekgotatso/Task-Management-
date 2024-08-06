from .. import mongo
from flask import jsonify
  
class Admin:
  
   def create_user(user_data):
        return mongo.db.admin.insert_one(user_data)