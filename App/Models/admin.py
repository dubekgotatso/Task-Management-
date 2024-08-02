from .. import mongo

class Admin:
      def create_user(signupdetails):
        existing_user = Admin.find_user_by_username_or_email(signupdetails['username'], signupdetails['email'])
        if existing_user:
            return False  # User already exists
        else:
            # Insert the new user into the database
            mongo.db.signup.insert_one(signupdetails)
            return True  # User created successfully