from .. import mongo


class User_Admin:
   
    
    def __init__(self, email, username, password, role):
        self.email = email
        self.username = username
        self.password = password
        self.role = role

    def save(self):
        mongo.db.user_admin.insert_one({
            "email": self.email,
            "username": self.username,
            "password": self.password,
            "role": self.role
        })

    @staticmethod
    def find_by_email(email):
        user_data = mongo.db.user_admin.find_one({"email": email})
        if user_data:
            return User_Admin(
                email=user_data['email'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data['role']
            )
        return None
    
  
    
        
        
     
   
        