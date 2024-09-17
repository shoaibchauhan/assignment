from mongoengine import Document, StringField, ReferenceField
import bcrypt

class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, choices=["user", "admin"], default="user")

    def set_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.password = hashed_password.decode('utf-8')

    def check_password(self, password):
        stored_password = self.password.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), stored_password)

    def is_admin(self):
        return self.role == "admin"

    def is_user(self):
        return self.role == "user"

class Project(Document):
    name = StringField(required=True,Unique=True)
    description = StringField(required=True)
    created_by = ReferenceField(User, required=True)
