from .. import mongo

class User:
    def create_user(signupdetails):
        existing_user = User.create_user(signupdetails['username'], signupdetails['email'])
        if existing_user:
            return False  # User already exists
        else:
            # Insert the new user into the database
            mongo.db.signup.insert_one(signupdetails)
            return True  # User created successfully